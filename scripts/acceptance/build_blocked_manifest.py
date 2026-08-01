#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

if __package__:
    from .catalog import canonical_json_bytes, load_catalog, sha256_bytes
else:
    from catalog import canonical_json_bytes, load_catalog, sha256_bytes


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--environment-manifest", type=Path, required=True)
    parser.add_argument("--release-candidate", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    try:
        _catalog, entries, catalog_raw = load_catalog(arguments.catalog)
        environment_raw = arguments.environment_manifest.read_bytes()
        if len(arguments.commit) != 40 or any(
            character not in "0123456789abcdef" for character in arguments.commit
        ):
            raise ValueError("commit must be a lowercase 40-character Git SHA-1")
        v1_ids = {
            entry.requirement_id
            for entry in entries
            if entry.requirement_priority == "V1-MUST"
        }
        manifest = {
            "schema_version": "1.0",
            "release_candidate": arguments.release_candidate,
            "commit_sha": arguments.commit,
            "generated_at": (
                datetime.now(UTC)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z")
            ),
            "requirements_catalog_sha256": sha256_bytes(catalog_raw),
            "environment_manifest_sha256": sha256_bytes(environment_raw),
            "coverage": {
                "expected_v1_must_count": len(v1_ids),
                "covered_v1_must_count": len(v1_ids),
                "catalog_exact_match": True,
                "missing_requirement_ids": [],
                "duplicate_requirement_test_pairs": [],
            },
            "gate_result": "BLOCKED",
            "entries": [
                {
                    **entry.document(),
                    "result": "NOT_RUN",
                    "evidence_level": "E0",
                    "oracle": None,
                    "evidence": [],
                    "executed_at": None,
                    "environment_id": None,
                }
                for entry in entries
            ],
            "defects": [],
            "known_limitations": [
                (
                    "This signed engineering candidate does not contain real "
                    "Windows, external-database, Discovery Gate, or production "
                    "acceptance evidence and is not approved for public release."
                )
            ],
        }
        raw = canonical_json_bytes(manifest)
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(
            arguments.output,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o644,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        print(
            json.dumps(
                {
                    "ready": True,
                    "code": "BLOCKED_ACCEPTANCE_MANIFEST_CREATED",
                    "sha256": sha256_bytes(raw),
                },
                sort_keys=True,
            )
        )
        return 0
    except (OSError, UnicodeError, TypeError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "ready": False,
                    "code": "ACCEPTANCE_MANIFEST_CREATE_FAILED",
                    "detail": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
