from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

SCHEMA_VERSION = "1.0"
EXPECTED_REQUIREMENT_COUNT = 81
EXPECTED_V1_MUST_COUNT = 80
EXPECTED_POST_V1_COUNT = 1

_REQUIREMENT_PATTERN = re.compile(
    r"`((?:PRD-(?:FR|BR)-[A-Z0-9-]+|NFR-[A-Z0-9-]+|ACC-PRD-[0-9]{3}))`"
)
_TEST_PATTERN = re.compile(
    r"`?((?:UT|CT|IT|E2E|UI|SEC|PERF|REC|OPS)-[A-Z0-9-]+)`?"
)
_EVIDENCE_PATTERN = re.compile(r"(?<![A-Z0-9])E[0-4](?![A-Z0-9])")


@dataclass(frozen=True, order=True)
class CatalogEntry:
    requirement_id: str
    requirement_priority: str
    test_id: str
    minimum_evidence_level: str

    def document(self) -> dict[str, str]:
        return {
            "requirement_id": self.requirement_id,
            "requirement_priority": self.requirement_priority,
            "test_id": self.test_id,
            "minimum_evidence_level": self.minimum_evidence_level,
        }


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
    requirements: dict[str, tuple[str, str, tuple[str, ...]]] = {}
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        requirement_ids = _REQUIREMENT_PATTERN.findall(line)
        if not requirement_ids:
            continue
        if len(requirement_ids) != 1:
            raise ValueError("a matrix row must contain exactly one requirement ID")
        requirement_id = requirement_ids[0]
        priorities = [
            priority
            for priority in ("V1-MUST", "POST-V1")
            if f"| {priority} |" in line
        ]
        test_ids = tuple(sorted(set(_TEST_PATTERN.findall(line))))
        evidence_levels = tuple(sorted(set(_EVIDENCE_PATTERN.findall(line))))
        if (
            len(priorities) != 1
            or not test_ids
            or len(evidence_levels) != 1
            or requirement_id in requirements
        ):
            raise ValueError(f"invalid or duplicate matrix row: {requirement_id}")
        requirements[requirement_id] = (
            priorities[0],
            evidence_levels[0],
            test_ids,
        )

    v1_count = sum(
        priority == "V1-MUST" for priority, _level, _tests in requirements.values()
    )
    post_v1_count = sum(
        priority == "POST-V1" for priority, _level, _tests in requirements.values()
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
            )
            for requirement_id, (
                priority,
                minimum_evidence_level,
                test_ids,
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
    return canonical_json_bytes(catalog_document(parse_requirements_matrix(matrix_path)))


def load_catalog(path: Path) -> tuple[dict[str, object], tuple[CatalogEntry, ...], bytes]:
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
        }:
            raise ValueError("requirements catalog entry shape is invalid")
        if not all(isinstance(value, str) for value in item.values()):
            raise ValueError("requirements catalog entry values must be strings")
        entries.append(CatalogEntry(**item))
    normalized = tuple(sorted(entries))
    expected_document = catalog_document(normalized)
    expected_raw = canonical_json_bytes(expected_document)
    if raw != expected_raw:
        raise ValueError("requirements catalog is not canonical")
    if document["schema_version"] != SCHEMA_VERSION:
        raise ValueError("requirements catalog schema version is unsupported")
    return document, normalized, raw
