from __future__ import annotations

import importlib.util
import json
import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

ORACLE_PATH = Path(__file__).parents[2] / "runtime" / "oracle" / "verification_oracle.py"
SPEC = importlib.util.spec_from_file_location("verification_oracle", ORACLE_PATH)
assert SPEC is not None and SPEC.loader is not None
oracle = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = oracle
SPEC.loader.exec_module(oracle)


def test_normalization_keeps_null_empty_and_literal_null_distinct() -> None:
    logical_types = ["TEXT"]

    digests = {
        oracle.row_sha256([None], logical_types),
        oracle.row_sha256([""], logical_types),
        oracle.row_sha256(["NULL"], logical_types),
    }

    assert len(digests) == 3


def test_unicode_decimal_timestamp_and_binary_are_canonical() -> None:
    logical_types = ["TEXT", "DECIMAL", "TIMESTAMP", "BINARY"]
    composed = [
        "é",
        Decimal("120.000"),
        datetime(2026, 7, 30, 12, 34, 56, 7, tzinfo=UTC),
        b"\x00\xff",
    ]
    decomposed = [
        "e\u0301",
        Decimal("120"),
        "2026-07-30T12:34:56.000007Z",
        memoryview(b"\x00\xff"),
    ]

    assert oracle.row_sha256(composed, logical_types) == oracle.row_sha256(
        decomposed,
        logical_types,
    )
    assert oracle.normalize_value(Decimal("-0.000"), "DECIMAL")[1] == b"0"


def test_multiset_is_order_independent_but_duplicate_sensitive() -> None:
    logical_types = ["INTEGER", "TEXT"]
    source = [[1, "a"], [2, "b"], [1, "a"]]
    reordered = [[2, "b"], [1, "a"], [1, "a"]]
    missing_duplicate = [[2, "b"], [1, "a"]]

    assert oracle.summarize_rows(source, logical_types) == oracle.summarize_rows(
        reordered,
        logical_types,
    )
    assert oracle.summarize_rows(source, logical_types) != oracle.summarize_rows(
        missing_duplicate,
        logical_types,
    )


def test_compare_rows_reports_missing_and_unexpected_counts() -> None:
    source, target, difference = oracle.compare_rows(
        [[1], [1], [2]],
        [[1], [3]],
        ["INTEGER"],
    )

    assert source.row_count == 3
    assert target.row_count == 2
    assert difference.missing_row_count == 2
    assert difference.unexpected_row_count == 1
    assert difference.row_count_equal is False
    assert difference.multiset_sha256_equal is False
    assert len(difference.sample_digest_pairs) == 3


def test_binary_float_is_rejected_for_decimal() -> None:
    with pytest.raises(oracle.NormalizationError):
        oracle.normalize_value(0.1, "DECIMAL")


def test_normalization_contract_fixes_binary_preimages() -> None:
    assert (
        oracle.NORMALIZATION_CONTRACT["field_encoding"]
        == "TAG_LENGTH_U16_BE_TAG_VALUE_LENGTH_U64_BE_VALUE"
    )
    assert (
        oracle.NORMALIZATION_CONTRACT["multiset_preimage"]
        == "DOMAIN_NUL_ROW_DIGEST_RAW32_COUNT_U64_BE"
    )


def test_disk_spool_streams_exact_duplicate_sensitive_multisets(
    tmp_path: Path,
) -> None:
    source_rows = ([value, f"row-{value % 7}"] for value in range(5000))
    target_rows = ([value, f"row-{value % 7}"] for value in reversed(range(5000)))

    with oracle.DigestSpool(tmp_path) as spool:
        assert (
            spool.add_rows(
                "source",
                source_rows,
                ["INTEGER", "TEXT"],
                batch_size=113,
            )
            == 5000
        )
        assert (
            spool.add_rows(
                "target",
                target_rows,
                ["INTEGER", "TEXT"],
                batch_size=127,
            )
            == 5000
        )
        source = spool.summary("source")
        target = spool.summary("target")
        difference = spool.difference()
        spool_path = spool.path

    assert source == target
    assert difference.missing_row_count == 0
    assert difference.unexpected_row_count == 0
    assert difference.sample_digest_pairs == []
    assert not spool_path.exists()


def test_disk_spool_reports_exact_missing_and_unexpected_counts(
    tmp_path: Path,
) -> None:
    with oracle.DigestSpool(tmp_path) as spool:
        spool.add_rows("source", [[1], [1], [2]], ["INTEGER"])
        spool.add_rows("target", [[1], [3]], ["INTEGER"])

        difference = spool.difference()

    assert difference.missing_row_count == 2
    assert difference.unexpected_row_count == 1
    assert len(difference.sample_digest_pairs) == 3


def test_report_builder_produces_schema_valid_rfc8785_artifact() -> None:
    schema = json.loads(
        (
            Path(__file__).parents[2] / "docs" / "contracts" / "verification-oracle.v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    start = datetime(2026, 7, 30, 1, 0, tzinfo=UTC)
    empty = oracle.summarize_rows([], ["INTEGER"])
    difference = oracle.DigestDifference(
        missing_row_count=0,
        unexpected_row_count=0,
        row_count_equal=True,
        multiset_sha256_equal=True,
        sample_digest_pairs=[],
    )

    report = oracle.build_verification_report(
        execution_id="e5046670-3d7b-4f6e-857e-e0983a31f407",
        job_version_id="e254f324-6c2a-474f-857d-f166bece63f1",
        started_at=start,
        finished_at=start.replace(minute=5),
        operator_confirmed_at=start,
        preflight_source_summary=empty,
        post_source_summary=empty,
        target_summary=empty,
        difference=difference,
        source_read_started_at=start.replace(minute=1),
        source_read_finished_at=start.replace(minute=2),
        target_read_started_at=start.replace(minute=3),
        target_read_finished_at=start.replace(minute=4),
        target_snapshot_id="pg:10:20:",
        target_snapshot_started_at=start.replace(minute=3),
        target_snapshot_finished_at=start.replace(minute=4),
        target_lock_key_hash="a" * 64,
        fence_epoch=1,
        target_lock_held=True,
        target_exclusivity={
            "statement_version": "1.0",
            "responsible_party": "DBA",
            "confirmed_at": start,
            "valid_until": start.replace(minute=10),
            "status": "ACTIVE",
            "revoked_at": None,
            "revocation_reason": None,
        },
        target_empty_checked_at=start.replace(minute=1),
        confirmation_evidence_sha256="b" * 64,
        mappings=[
            {
                "ordinal": 1,
                "source_column": "id",
                "target_column": "id",
                "logical_type": "INTEGER",
            }
        ],
    )

    errors = list(
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).iter_errors(report)
    )
    assert errors == []
    claimed = report.pop("artifact_sha256")
    assert claimed == oracle.artifact_sha256(report)
