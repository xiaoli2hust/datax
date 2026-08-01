"""Deterministic row-multiset oracle independent from DataX process metrics."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import unicodedata
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, date, datetime, time
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Self

import rfc8785

ROW_DOMAIN = b"DXORACLEROWv1\0"
MULTISET_DOMAIN = b"DXORACLEMULTISETv1\0"
SUPPORTED_LOGICAL_TYPES = frozenset(
    {
        "INTEGER",
        "DECIMAL",
        "TEXT",
        "BOOLEAN",
        "DATE",
        "TIME",
        "TIMESTAMP",
        "BINARY",
    }
)
NORMALIZATION_CONTRACT = {
    "row_algorithm": "SHA-256",
    "row_preimage": "DOMAIN_NUL_FIELD_COUNT_U32_BE_FIELDS",
    "field_encoding": "TAG_LENGTH_U16_BE_TAG_VALUE_LENGTH_U64_BE_VALUE",
    "collection_semantics": "MULTISET_WITH_COUNTS",
    "stable_order": "ROW_DIGEST_ASC_THEN_COUNT",
    "multiset_preimage": "DOMAIN_NUL_ROW_DIGEST_RAW32_COUNT_U64_BE",
    "null_encoding": "TYPE_TAGGED_NULL",
    "text_encoding": "UTF-8",
    "unicode_normalization": "NFC",
    "trim_text": False,
    "decimal_encoding": "CANONICAL_BASE10_NO_EXPONENT_NO_INSIGNIFICANT_ZERO",
    "negative_zero": "NORMALIZE_TO_ZERO",
    "session_timezone": "UTC",
    "timestamp_encoding": "RFC3339_UTC_MICROSECONDS",
    "boolean_encoding": "LOWERCASE_TRUE_FALSE",
    "binary_encoding": "BASE64_RFC4648",
    "field_separator": "LENGTH_PREFIXED",
}


class NormalizationError(ValueError):
    """Raised when a value cannot be encoded without semantic ambiguity."""


@dataclass(frozen=True)
class MultisetSummary:
    row_count: int
    distinct_row_digest_count: int
    multiset_sha256: str


@dataclass(frozen=True)
class DigestDifference:
    missing_row_count: int
    unexpected_row_count: int
    row_count_equal: bool
    multiset_sha256_equal: bool
    sample_digest_pairs: list[dict[str, int | str]]


@dataclass
class DigestSpool:
    """Disk-backed exact row-digest multiset used for bounded-memory DB reads.

    Only SHA-256 row digests and occurrence counts are written to the spool.
    Source and target values, credentials, and SQL are never persisted here.
    """

    directory: Path
    _path: Path = field(init=False, repr=False)
    _connection: sqlite3.Connection = field(init=False, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        resolved = self.directory.resolve()
        resolved.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.directory.is_symlink() or not resolved.is_dir():
            raise ValueError("digest spool directory must be a regular directory")
        descriptor, raw_path = tempfile.mkstemp(
            prefix="oracle-digests-",
            suffix=".sqlite3",
            dir=resolved,
        )
        os.fchmod(descriptor, 0o600)
        os.close(descriptor)
        self._path = Path(raw_path)
        self._connection = sqlite3.connect(raw_path)
        self._connection.executescript(
            """
            PRAGMA journal_mode=OFF;
            PRAGMA synchronous=OFF;
            PRAGMA temp_store=FILE;
            CREATE TABLE digest_counts (
                side TEXT NOT NULL CHECK (side IN ('source', 'target')),
                digest BLOB NOT NULL CHECK (length(digest) = 32),
                occurrence_count INTEGER NOT NULL CHECK (occurrence_count > 0),
                PRIMARY KEY (side, digest)
            ) WITHOUT ROWID;
            """
        )

    @property
    def path(self) -> Path:
        return self._path

    def add_rows(
        self,
        side: str,
        rows: Iterable[Sequence[Any]],
        logical_types: Sequence[str],
        *,
        batch_size: int = 1000,
    ) -> int:
        if side not in {"source", "target"}:
            raise ValueError("side must be source or target")
        if batch_size < 1 or batch_size > 100_000:
            raise ValueError("batch_size must be between 1 and 100000")
        if not logical_types:
            raise NormalizationError("at least one mapped column is required")
        observed = 0
        batch: Counter[bytes] = Counter()
        for row in rows:
            batch[bytes.fromhex(row_sha256(row, logical_types))] += 1
            observed += 1
            if observed % batch_size == 0:
                self._flush(side, batch)
                batch.clear()
        self._flush(side, batch)
        return observed

    def _flush(self, side: str, counts: Counter[bytes]) -> None:
        if not counts:
            return
        with self._connection:
            self._connection.executemany(
                """
                INSERT INTO digest_counts (side, digest, occurrence_count)
                VALUES (?, ?, ?)
                ON CONFLICT (side, digest) DO UPDATE
                SET occurrence_count =
                    digest_counts.occurrence_count + excluded.occurrence_count
                """,
                [(side, digest, count) for digest, count in counts.items()],
            )

    def summary(self, side: str) -> MultisetSummary:
        if side not in {"source", "target"}:
            raise ValueError("side must be source or target")
        digest = hashlib.sha256(MULTISET_DOMAIN)
        row_count = 0
        distinct = 0
        cursor = self._connection.execute(
            """
            SELECT digest, occurrence_count
            FROM digest_counts
            WHERE side = ?
            ORDER BY digest ASC
            """,
            (side,),
        )
        for raw_digest, count in cursor:
            digest.update(raw_digest)
            digest.update(count.to_bytes(8, byteorder="big"))
            row_count += count
            distinct += 1
        return MultisetSummary(
            row_count=row_count,
            distinct_row_digest_count=distinct,
            multiset_sha256=digest.hexdigest(),
        )

    def difference(self, *, sample_limit: int = 20) -> DigestDifference:
        if sample_limit < 0 or sample_limit > 20:
            raise ValueError("sample_limit must be between 0 and 20")
        source = self.summary("source")
        target = self.summary("target")
        missing = 0
        unexpected = 0
        samples: list[dict[str, int | str]] = []
        rows = self._connection.execute(
            """
            SELECT
                hex(digest) AS digest_hex,
                SUM(CASE WHEN side = 'source' THEN occurrence_count ELSE 0 END)
                    AS source_count,
                SUM(CASE WHEN side = 'target' THEN occurrence_count ELSE 0 END)
                    AS target_count
            FROM digest_counts
            GROUP BY digest
            HAVING
                SUM(CASE WHEN side = 'source' THEN occurrence_count ELSE 0 END)
                !=
                SUM(CASE WHEN side = 'target' THEN occurrence_count ELSE 0 END)
            ORDER BY digest ASC
            """
        )
        for digest_hex, source_count, target_count in rows:
            missing += max(source_count - target_count, 0)
            unexpected += max(target_count - source_count, 0)
            if len(samples) < sample_limit:
                samples.append(
                    {
                        "row_sha256": digest_hex.lower(),
                        "source_count": source_count,
                        "target_count": target_count,
                    }
                )
        return DigestDifference(
            missing_row_count=missing,
            unexpected_row_count=unexpected,
            row_count_equal=source.row_count == target.row_count,
            multiset_sha256_equal=(source.multiset_sha256 == target.multiset_sha256),
            sample_digest_pairs=samples,
        )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._connection.close()
        try:
            self._path.unlink()
        except FileNotFoundError:
            pass

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


def _canonical_decimal(value: Any) -> str:
    if isinstance(value, (bool, float)):
        raise NormalizationError(
            "DECIMAL must not be derived from binary floating point"
        )
    try:
        decimal_value = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise NormalizationError("invalid DECIMAL value") from exc
    if not decimal_value.is_finite():
        raise NormalizationError("DECIMAL must be finite")
    if decimal_value.is_zero():
        return "0"
    rendered = format(decimal_value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered


def _canonical_timestamp(value: Any) -> str:
    try:
        parsed = (
            datetime.fromisoformat(value.replace("Z", "+00:00"))
            if isinstance(value, str)
            else value
        )
    except ValueError as exc:
        raise NormalizationError("invalid TIMESTAMP value") from exc
    if not isinstance(parsed, datetime):
        raise NormalizationError("TIMESTAMP requires a datetime value")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _canonical_date(value: Any) -> str:
    try:
        parsed = date.fromisoformat(value) if isinstance(value, str) else value
    except ValueError as exc:
        raise NormalizationError("invalid DATE value") from exc
    if isinstance(parsed, datetime) or not isinstance(parsed, date):
        raise NormalizationError("DATE requires a date without a time")
    return parsed.isoformat()


def _canonical_time(value: Any) -> str:
    try:
        parsed = time.fromisoformat(value) if isinstance(value, str) else value
    except ValueError as exc:
        raise NormalizationError("invalid TIME value") from exc
    if not isinstance(parsed, time):
        raise NormalizationError("TIME requires a time value")
    if parsed.tzinfo is not None and parsed.utcoffset() not in (
        None,
        UTC.utcoffset(None),
    ):
        raise NormalizationError(
            "TIME with a non-UTC offset is ambiguous without a date"
        )
    return parsed.replace(tzinfo=None).isoformat(timespec="microseconds")


def _canonical_integer(value: Any) -> str:
    if isinstance(value, bool):
        raise NormalizationError("BOOLEAN is not an INTEGER")
    if isinstance(value, int):
        return str(value)
    if (
        isinstance(value, Decimal)
        and value.is_finite()
        and value == value.to_integral_value()
    ):
        return str(int(value))
    raise NormalizationError("INTEGER requires an exact integer value")


def normalize_value(value: Any, logical_type: str) -> tuple[bytes, bytes]:
    logical_type = logical_type.upper()
    if logical_type not in SUPPORTED_LOGICAL_TYPES:
        raise NormalizationError(f"unsupported logical type: {logical_type}")
    if value is None:
        return b"NULL", b""
    if logical_type == "INTEGER":
        return b"INTEGER", _canonical_integer(value).encode("ascii")
    if logical_type == "DECIMAL":
        return b"DECIMAL", _canonical_decimal(value).encode("ascii")
    if logical_type == "TEXT":
        if not isinstance(value, str):
            raise NormalizationError("TEXT requires a Unicode string")
        return b"TEXT", unicodedata.normalize("NFC", value).encode("utf-8")
    if logical_type == "BOOLEAN":
        if not isinstance(value, bool):
            raise NormalizationError("BOOLEAN requires a bool value")
        return b"BOOLEAN", (b"true" if value else b"false")
    if logical_type == "DATE":
        return b"DATE", _canonical_date(value).encode("ascii")
    if logical_type == "TIME":
        return b"TIME", _canonical_time(value).encode("ascii")
    if logical_type == "TIMESTAMP":
        return b"TIMESTAMP", _canonical_timestamp(value).encode("ascii")
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise NormalizationError("BINARY requires bytes")
    return b"BINARY", base64.b64encode(bytes(value))


def encode_field(value: Any, logical_type: str) -> bytes:
    tag, encoded_value = normalize_value(value, logical_type)
    return (
        len(tag).to_bytes(2, byteorder="big")
        + tag
        + len(encoded_value).to_bytes(8, byteorder="big")
        + encoded_value
    )


def row_sha256(row: Sequence[Any], logical_types: Sequence[str]) -> str:
    if len(row) != len(logical_types):
        raise NormalizationError("row width does not match mapping width")
    digest = hashlib.sha256(ROW_DOMAIN)
    digest.update(len(row).to_bytes(4, byteorder="big"))
    for value, logical_type in zip(row, logical_types, strict=True):
        digest.update(encode_field(value, logical_type))
    return digest.hexdigest()


def digest_counts(
    rows: Iterable[Sequence[Any]],
    logical_types: Sequence[str],
) -> Counter[str]:
    if not logical_types:
        raise NormalizationError("at least one mapped column is required")
    return Counter(row_sha256(row, logical_types) for row in rows)


def summarize_digest_counts(counts: Counter[str]) -> MultisetSummary:
    digest = hashlib.sha256(MULTISET_DOMAIN)
    row_count = 0
    for row_digest, count in sorted(counts.items()):
        if len(row_digest) != 64 or count <= 0:
            raise NormalizationError("invalid row digest multiset")
        digest.update(bytes.fromhex(row_digest))
        digest.update(count.to_bytes(8, byteorder="big"))
        row_count += count
    return MultisetSummary(
        row_count=row_count,
        distinct_row_digest_count=len(counts),
        multiset_sha256=digest.hexdigest(),
    )


def summarize_rows(
    rows: Iterable[Sequence[Any]],
    logical_types: Sequence[str],
) -> MultisetSummary:
    return summarize_digest_counts(digest_counts(rows, logical_types))


def compare_rows(
    source_rows: Iterable[Sequence[Any]],
    target_rows: Iterable[Sequence[Any]],
    logical_types: Sequence[str],
    *,
    sample_limit: int = 20,
) -> tuple[MultisetSummary, MultisetSummary, DigestDifference]:
    if sample_limit < 0 or sample_limit > 20:
        raise ValueError("sample_limit must be between 0 and 20")
    source_counts = digest_counts(source_rows, logical_types)
    target_counts = digest_counts(target_rows, logical_types)
    source_summary = summarize_digest_counts(source_counts)
    target_summary = summarize_digest_counts(target_counts)
    missing = source_counts - target_counts
    unexpected = target_counts - source_counts
    differing_digests = sorted(set(missing) | set(unexpected))
    samples = [
        {
            "row_sha256": row_digest,
            "source_count": source_counts[row_digest],
            "target_count": target_counts[row_digest],
        }
        for row_digest in differing_digests[:sample_limit]
    ]
    difference = DigestDifference(
        missing_row_count=sum(missing.values()),
        unexpected_row_count=sum(unexpected.values()),
        row_count_equal=source_summary.row_count == target_summary.row_count,
        multiset_sha256_equal=(
            source_summary.multiset_sha256 == target_summary.multiset_sha256
        ),
        sample_digest_pairs=samples,
    )
    return source_summary, target_summary, difference


def summary_fingerprint(summary: MultisetSummary) -> str:
    return hashlib.sha256(
        b"DXORACLESOURCEFINGERPRINTv1\0"
        + summary.row_count.to_bytes(8, "big")
        + summary.distinct_row_digest_count.to_bytes(8, "big")
        + bytes.fromhex(summary.multiset_sha256)
    ).hexdigest()


def artifact_sha256(report_without_hash: dict[str, Any]) -> str:
    if "artifact_sha256" in report_without_hash:
        raise ValueError("artifact hash input must not contain artifact_sha256")
    return hashlib.sha256(rfc8785.dumps(report_without_hash)).hexdigest()


def build_verification_report(
    *,
    execution_id: str,
    job_version_id: str,
    started_at: datetime,
    finished_at: datetime,
    operator_confirmed_at: datetime,
    preflight_source_summary: MultisetSummary,
    post_source_summary: MultisetSummary | None,
    target_summary: MultisetSummary | None,
    difference: DigestDifference | None,
    source_read_started_at: datetime | None,
    source_read_finished_at: datetime | None,
    target_read_started_at: datetime | None,
    target_read_finished_at: datetime | None,
    target_snapshot_id: str | None,
    target_snapshot_started_at: datetime | None,
    target_snapshot_finished_at: datetime | None,
    target_lock_key_hash: str,
    fence_epoch: int,
    target_lock_held: bool,
    target_exclusivity: dict[str, Any],
    target_empty_checked_at: datetime,
    confirmation_evidence_sha256: str,
    mappings: Sequence[dict[str, Any]],
    inconclusive_reason: str | None = None,
) -> dict[str, Any]:
    """Build the versioned oracle artifact from independent DB read evidence."""

    source_pre_fingerprint = summary_fingerprint(preflight_source_summary)
    source_post_fingerprint = (
        summary_fingerprint(post_source_summary)
        if post_source_summary is not None
        else source_pre_fingerprint
    )
    unchanged = (
        post_source_summary is not None
        and source_pre_fingerprint == source_post_fingerprint
    )
    active_exclusivity = (
        target_exclusivity.get("status") == "ACTIVE"
        and target_exclusivity.get("revoked_at") is None
        and target_exclusivity.get("revocation_reason") is None
    )
    valid_until = _as_utc_datetime(target_exclusivity["valid_until"])
    snapshot_within_window = (
        target_snapshot_finished_at is not None
        and _as_utc_datetime(target_snapshot_finished_at) <= valid_until
    )
    comparable = (
        post_source_summary is not None
        and target_summary is not None
        and difference is not None
    )

    if inconclusive_reason is not None:
        result = "INCONCLUSIVE"
    elif not unchanged:
        result = "INCONCLUSIVE"
        inconclusive_reason = "SOURCE_QUIESCENCE_BROKEN"
    elif not target_lock_held:
        result = "INCONCLUSIVE"
        inconclusive_reason = "TARGET_LOCK_LOST"
    elif not active_exclusivity or not snapshot_within_window:
        result = "INCONCLUSIVE"
        inconclusive_reason = "TARGET_EXCLUSIVITY_BROKEN"
    elif not comparable:
        result = "INCONCLUSIVE"
        inconclusive_reason = "ORACLE_INTERNAL_ERROR"
    elif (
        difference.missing_row_count == 0
        and difference.unexpected_row_count == 0
        and difference.row_count_equal
        and difference.multiset_sha256_equal
    ):
        result = "PASSED"
    else:
        result = "FAILED"

    report: dict[str, Any] = {
        "schema_version": "1.0",
        "oracle_version": "oracle-v1.0",
        "execution_id": execution_id,
        "job_version_id": job_version_id,
        "started_at": _rfc3339(started_at),
        "finished_at": _rfc3339(finished_at),
        "source_quiescence": {
            "mode": "OPERATOR_QUIESCED",
            "operator_confirmed_at": _rfc3339(operator_confirmed_at),
            "preflight_fingerprint": source_pre_fingerprint,
            "post_verification_fingerprint": source_post_fingerprint,
            "unchanged": unchanged,
        },
        "target_lock": {
            "lock_key_hash": target_lock_key_hash,
            "fence_epoch": fence_epoch,
            "held_through_verification": target_lock_held,
        },
        "target_exclusivity": {
            "mode": "OPERATOR_OR_DBA_CONFIRMED",
            "statement_version": target_exclusivity["statement_version"],
            "responsible_party": target_exclusivity["responsible_party"],
            "confirmed_at": _rfc3339(
                _as_utc_datetime(target_exclusivity["confirmed_at"])
            ),
            "valid_until": _rfc3339(valid_until),
            "status": target_exclusivity["status"],
            "revoked_at": (
                _rfc3339(_as_utc_datetime(target_exclusivity["revoked_at"]))
                if target_exclusivity.get("revoked_at") is not None
                else None
            ),
            "revocation_reason": target_exclusivity.get("revocation_reason"),
            "target_empty_checked_at": _rfc3339(target_empty_checked_at),
            "target_snapshot_id": target_snapshot_id,
            "valid_through_target_snapshot": (
                active_exclusivity and snapshot_within_window
            ),
            "confirmation_evidence_sha256": confirmation_evidence_sha256,
        },
        "normalization": NORMALIZATION_CONTRACT,
        "mapping_order": list(mappings),
        "source_result": (
            {
                **asdict(post_source_summary),
                "read_started_at": _rfc3339(source_read_started_at),
                "read_finished_at": _rfc3339(source_read_finished_at),
            }
            if post_source_summary is not None
            and source_read_started_at is not None
            and source_read_finished_at is not None
            else None
        ),
        "target_result": (
            {
                **asdict(target_summary),
                "read_started_at": _rfc3339(target_read_started_at),
                "read_finished_at": _rfc3339(target_read_finished_at),
                "snapshot_mode": "SINGLE_CONSISTENT_READ_TRANSACTION",
                "snapshot_id": target_snapshot_id,
                "snapshot_started_at": _rfc3339(target_snapshot_started_at),
                "snapshot_finished_at": _rfc3339(target_snapshot_finished_at),
            }
            if target_summary is not None
            and target_read_started_at is not None
            and target_read_finished_at is not None
            and target_snapshot_id is not None
            and target_snapshot_started_at is not None
            and target_snapshot_finished_at is not None
            else None
        ),
        "difference": asdict(difference) if difference is not None else None,
        "result": result,
        "inconclusive_reason": inconclusive_reason,
    }
    report["artifact_sha256"] = artifact_sha256(report)
    return report


def _as_utc_datetime(value: str | datetime) -> datetime:
    parsed = (
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        if isinstance(value, str)
        else value
    )
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("oracle timestamps must include an offset")
    return parsed.astimezone(UTC)


def _rfc3339(value: datetime | None) -> str:
    if value is None:
        raise ValueError("oracle timestamp is required")
    return (
        _as_utc_datetime(value)
        .isoformat(timespec="microseconds")
        .replace(
            "+00:00",
            "Z",
        )
    )


def _decode_json_value(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    if set(value) == {"$decimal"}:
        return Decimal(value["$decimal"])
    if set(value) == {"$binary_base64"}:
        try:
            return base64.b64decode(value["$binary_base64"], validate=True)
        except (TypeError, ValueError) as exc:
            raise NormalizationError("invalid base64 fixture value") from exc
    if set(value) == {"$timestamp"}:
        return _canonical_timestamp(value["$timestamp"])
    if set(value) == {"$date"}:
        return date.fromisoformat(value["$date"])
    if set(value) == {"$time"}:
        return time.fromisoformat(value["$time"])
    raise NormalizationError("unsupported typed JSON fixture value")


def _read_jsonl(path: Path) -> list[list[Any]]:
    rows: list[list[Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, list):
                raise NormalizationError(f"line {line_number} is not a JSON array")
            rows.append([_decode_json_value(item) for item in value])
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(prog="verification-oracle")
    parser.add_argument("--logical-types", required=True)
    parser.add_argument("--source-jsonl", type=Path, required=True)
    parser.add_argument("--target-jsonl", type=Path, required=True)
    arguments = parser.parse_args()
    logical_types = [
        item.strip().upper() for item in arguments.logical_types.split(",")
    ]
    try:
        source_summary, target_summary, difference = compare_rows(
            _read_jsonl(arguments.source_jsonl),
            _read_jsonl(arguments.target_jsonl),
            logical_types,
        )
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        NormalizationError,
        ValueError,
    ) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "oracle_version": "oracle-v1.0",
                "source_result": asdict(source_summary),
                "target_result": asdict(target_summary),
                "difference": asdict(difference),
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
