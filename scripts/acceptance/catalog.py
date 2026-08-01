from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

SCHEMA_VERSION = "1.1"
EXPECTED_REQUIREMENT_COUNT = 81
EXPECTED_V1_MUST_COUNT = 80
EXPECTED_POST_V1_COUNT = 1

_REQUIREMENT_PATTERN = re.compile(
    r"^(?:`)?((?:PRD-(?:FR|BR)-[A-Z0-9-]+|NFR-[A-Z0-9-]+|ACC-PRD-[0-9]{3}))(?:`)?$"
)
_TEST_PATTERN = re.compile(
    r"(?:`)?((?:UT|CT|IT|E2E|UI|SEC|PERF|REC|OPS)-[A-Z0-9-]+)(?:`)?"
)
_EVIDENCE_PATTERN = re.compile(r"^(E[0-4])(?:\s|$)")

VERIFICATION_ORACLE_V1 = "VERIFICATION_ORACLE_V1"
WINDOWS_E4 = "WINDOWS_E4"


@dataclass(frozen=True, order=True)
class CatalogEntry:
    requirement_id: str
    requirement_priority: str
    test_id: str
    minimum_evidence_level: str
    evidence_requirements: tuple[str, ...]

    def document(self) -> dict[str, object]:
        return {
            "requirement_id": self.requirement_id,
            "requirement_priority": self.requirement_priority,
            "test_id": self.test_id,
            "minimum_evidence_level": self.minimum_evidence_level,
            "evidence_requirements": list(self.evidence_requirements),
        }


def _split_markdown_row(line: str) -> tuple[str, ...]:
    """Split one pipe table row without treating an escaped pipe as a column."""

    if not line.startswith("|") or not line.endswith("|"):
        raise ValueError("Markdown table rows must start and end with a pipe")
    cells: list[str] = []
    current: list[str] = []
    escaped = False
    for character in line[1:-1]:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            current.append(character)
            escaped = True
        elif character == "|":
            cells.append("".join(current).strip())
            current = []
        else:
            current.append(character)
    if escaped:
        raise ValueError("Markdown table row ends with an incomplete escape")
    cells.append("".join(current).strip())
    return tuple(cells)


def _is_separator_row(cells: tuple[str, ...]) -> bool:
    return bool(cells) and all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells)


def _parse_test_ids(cell: str) -> tuple[str, ...]:
    matches = tuple(_TEST_PATTERN.findall(cell))
    residual = _TEST_PATTERN.sub("", cell)
    residual = residual.replace("、", "").replace(",", "").strip()
    if not matches or residual:
        raise ValueError(f"invalid test ID cell: {cell}")
    if len(set(matches)) != len(matches):
        raise ValueError(f"duplicate test ID in cell: {cell}")
    return tuple(matches)


def _evidence_requirements(
    *, oracle_cell: str, evidence_cell: str, minimum_evidence_level: str
) -> tuple[str, ...]:
    requirements: list[str] = []
    if "oracle-v1" in f"{oracle_cell} {evidence_cell}".casefold():
        requirements.append(VERIFICATION_ORACLE_V1)
    if minimum_evidence_level == "E4":
        requirements.append(WINDOWS_E4)
    return tuple(requirements)


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def parse_requirements_matrix(path: Path) -> tuple[CatalogEntry, ...]:
    text = path.read_text(encoding="utf-8")
    requirements: dict[str, tuple[str, str, tuple[str, ...], tuple[str, ...]]] = {}
    header: tuple[str, ...] | None = None
    for line in text.splitlines():
        if not line.startswith("|"):
            header = None
            continue
        cells = _split_markdown_row(line)
        if _is_separator_row(cells):
            continue
        id_column = next(
            (name for name in ("需求 ID", "规则 ID", "验收 ID") if name in cells),
            None,
        )
        if id_column is not None and {
            "需求级别",
            "测试 ID",
            "Oracle",
            "最低证据",
        }.issubset(cells):
            header = cells
            continue
        if header is None or len(cells) != len(header):
            continue
        row = dict(zip(header, cells, strict=True))
        id_column = next(
            name for name in ("需求 ID", "规则 ID", "验收 ID") if name in row
        )
        requirement_match = _REQUIREMENT_PATTERN.fullmatch(row[id_column])
        if requirement_match is None:
            continue
        requirement_id = requirement_match.group(1)
        priority = row["需求级别"]
        evidence_match = _EVIDENCE_PATTERN.match(row["最低证据"])
        if (
            priority not in {"V1-MUST", "POST-V1"}
            or evidence_match is None
            or requirement_id in requirements
        ):
            raise ValueError(f"invalid or duplicate matrix row: {requirement_id}")
        minimum_evidence_level = evidence_match.group(1)
        test_ids = _parse_test_ids(row["测试 ID"])
        requirements[requirement_id] = (
            priority,
            minimum_evidence_level,
            test_ids,
            _evidence_requirements(
                oracle_cell=row["Oracle"],
                evidence_cell=row.get("证据字段", ""),
                minimum_evidence_level=minimum_evidence_level,
            ),
        )

    v1_count = sum(
        priority == "V1-MUST"
        for priority, _level, _tests, _requirements in requirements.values()
    )
    post_v1_count = sum(
        priority == "POST-V1"
        for priority, _level, _tests, _requirements in requirements.values()
    )
    if (
        len(requirements) != EXPECTED_REQUIREMENT_COUNT
        or v1_count != EXPECTED_V1_MUST_COUNT
        or post_v1_count != EXPECTED_POST_V1_COUNT
    ):
        raise ValueError(
            "matrix requirement counts do not match the frozen V1.2 catalog"
        )

    entries = tuple(
        sorted(
            CatalogEntry(
                requirement_id=requirement_id,
                requirement_priority=priority,
                test_id=test_id,
                minimum_evidence_level=minimum_evidence_level,
                evidence_requirements=evidence_requirements,
            )
            for requirement_id, (
                priority,
                minimum_evidence_level,
                test_ids,
                evidence_requirements,
            ) in requirements.items()
            for test_id in test_ids
        )
    )
    pairs = {(entry.requirement_id, entry.test_id) for entry in entries}
    if len(pairs) != len(entries):
        raise ValueError("matrix contains duplicate requirement/test pairs")
    return entries


def catalog_document(entries: tuple[CatalogEntry, ...]) -> dict[str, object]:
    unique_ids = {entry.requirement_id for entry in entries}
    v1_ids = {
        entry.requirement_id
        for entry in entries
        if entry.requirement_priority == "V1-MUST"
    }
    post_v1_ids = {
        entry.requirement_id
        for entry in entries
        if entry.requirement_priority == "POST-V1"
    }
    if (
        len(unique_ids) != EXPECTED_REQUIREMENT_COUNT
        or len(v1_ids) != EXPECTED_V1_MUST_COUNT
        or len(post_v1_ids) != EXPECTED_POST_V1_COUNT
    ):
        raise ValueError("catalog entry counts are invalid")
    return {
        "schema_version": SCHEMA_VERSION,
        "requirement_count": len(unique_ids),
        "v1_must_count": len(v1_ids),
        "post_v1_count": len(post_v1_ids),
        "entry_count": len(entries),
        "entries": [entry.document() for entry in entries],
    }


def build_catalog_bytes(matrix_path: Path) -> bytes:
    return canonical_json_bytes(
        catalog_document(parse_requirements_matrix(matrix_path))
    )


def load_catalog(
    path: Path,
) -> tuple[dict[str, object], tuple[CatalogEntry, ...], bytes]:
    raw = path.read_bytes()
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("requirements catalog is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "requirement_count",
        "v1_must_count",
        "post_v1_count",
        "entry_count",
        "entries",
    }:
        raise ValueError("requirements catalog shape is invalid")
    raw_entries = document["entries"]
    if not isinstance(raw_entries, list):
        raise TypeError("requirements catalog entries must be an array")
    entries: list[CatalogEntry] = []
    for item in raw_entries:
        if not isinstance(item, dict) or set(item) != {
            "requirement_id",
            "requirement_priority",
            "test_id",
            "minimum_evidence_level",
            "evidence_requirements",
        }:
            raise ValueError("requirements catalog entry shape is invalid")
        string_fields = {
            key: value for key, value in item.items() if key != "evidence_requirements"
        }
        raw_evidence_requirements = item["evidence_requirements"]
        if (
            not all(isinstance(value, str) for value in string_fields.values())
            or not isinstance(raw_evidence_requirements, list)
            or not all(isinstance(value, str) for value in raw_evidence_requirements)
            or raw_evidence_requirements != sorted(set(raw_evidence_requirements))
            or any(
                value not in {VERIFICATION_ORACLE_V1, WINDOWS_E4}
                for value in raw_evidence_requirements
            )
        ):
            raise ValueError("requirements catalog entry values must be strings")
        entries.append(
            CatalogEntry(
                **string_fields,
                evidence_requirements=tuple(raw_evidence_requirements),
            )
        )
    normalized = tuple(sorted(entries))
    expected_document = catalog_document(normalized)
    expected_raw = canonical_json_bytes(expected_document)
    if raw != expected_raw:
        raise ValueError("requirements catalog is not canonical")
    if document["schema_version"] != SCHEMA_VERSION:
        raise ValueError("requirements catalog schema version is unsupported")
    return document, normalized, raw
