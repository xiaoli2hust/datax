from __future__ import annotations

import sys
import tempfile
import unittest
from copy import deepcopy
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from evaluate_osv_report import (
    EvaluationInputError,
    _read_json,
    evaluate,
)

AS_OF = date(2026, 7, 31)
LONG_REASON = (
    "The fixed runtime configuration does not expose the vulnerable code path; "
    "the exception is bounded to this exact package version pending replacement."
)


def manifest(*exceptions: dict[str, str]) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "scope": {
            "ecosystems": ["Maven", "PyPI", "Go", "npm", "crates.io"]
        },
        "exceptions": list(exceptions),
    }


def exception(
    *,
    vulnerability_id: str = "GHSA-test-0000-0000",
    ecosystem: str = "Maven",
    name: str = "example:library",
    version: str = "1.0.0",
    expires: str = "2026-09-30",
) -> dict[str, str]:
    return {
        "vulnerability_id": vulnerability_id,
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "reason": LONG_REASON,
        "expires": expires,
    }


def report(
    *,
    ids: list[str] | None = None,
    aliases: list[str] | None = None,
    ecosystem: str = "Maven",
    name: str = "example:library",
    version: str = "1.0.0",
) -> dict[str, object]:
    return {
        "results": [
            {
                "source": {"path": "worker.spdx.json", "type": "sbom"},
                "packages": [
                    {
                        "package": {
                            "ecosystem": ecosystem,
                            "name": name,
                            "version": version,
                        },
                        "groups": [
                            {
                                "ids": ids or ["GHSA-test-0000-0000"],
                                "aliases": aliases or ["CVE-2026-0001"],
                                "max_severity": "7.5",
                            }
                        ],
                    },
                    {
                        "package": {
                            "ecosystem": "Debian",
                            "name": "ignored-os-package",
                            "version": "1",
                        },
                        "groups": [{"ids": ["DEBIAN-CVE-1"]}],
                    },
                ],
            }
        ]
    }


class EvaluateOsvReportTests(unittest.TestCase):
    def test_exact_exception_passes_and_non_application_package_is_ignored(self) -> None:
        result = evaluate(report(), manifest(exception()), as_of=AS_OF)

        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["summary"]["application_findings"], 1)
        self.assertEqual(result["summary"]["excepted_findings"], 1)

    def test_unexcepted_finding_fails(self) -> None:
        result = evaluate(report(), manifest(), as_of=AS_OF)

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["summary"]["unexcepted_findings"], 1)

    def test_expired_exception_is_invalid(self) -> None:
        with self.assertRaisesRegex(EvaluationInputError, "expired"):
            evaluate(
                report(),
                manifest(exception(expires="2026-07-30")),
                as_of=AS_OF,
            )

    def test_exception_expiring_on_evaluation_date_is_invalid(self) -> None:
        with self.assertRaisesRegex(EvaluationInputError, "expired"):
            evaluate(
                report(),
                manifest(exception(expires="2026-07-31")),
                as_of=AS_OF,
            )

    def test_exception_cannot_extend_more_than_ninety_days(self) -> None:
        with self.assertRaisesRegex(EvaluationInputError, "more than 90 days"):
            evaluate(
                report(),
                manifest(exception(expires="2026-10-30")),
                as_of=AS_OF,
            )

    def test_unused_exception_fails(self) -> None:
        result = evaluate(
            report(),
            manifest(exception(version="2.0.0")),
            as_of=AS_OF,
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["summary"]["unused_exceptions"], 1)

    def test_duplicate_exact_binding_is_invalid(self) -> None:
        first = exception()
        with self.assertRaisesRegex(EvaluationInputError, "duplicates"):
            evaluate(
                report(),
                manifest(first, deepcopy(first)),
                as_of=AS_OF,
            )

    def test_primary_and_alias_exceptions_for_one_group_are_ambiguous(self) -> None:
        result = evaluate(
            report(aliases=["CVE-2026-0001"]),
            manifest(
                exception(),
                exception(vulnerability_id="CVE-2026-0001"),
            ),
            as_of=AS_OF,
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["summary"]["ambiguous_matches"], 1)

    def test_malformed_application_group_is_invalid(self) -> None:
        malformed = report()
        malformed["results"][0]["packages"][0]["groups"][0]["ids"] = []

        with self.assertRaisesRegex(EvaluationInputError, "must not be empty"):
            evaluate(malformed, manifest(), as_of=AS_OF)

    def test_scope_cannot_omit_an_application_ecosystem(self) -> None:
        incomplete_manifest = manifest()
        incomplete_manifest["scope"] = {"ecosystems": ["Maven"]}

        with self.assertRaisesRegex(EvaluationInputError, "exactly"):
            evaluate(report(), incomplete_manifest, as_of=AS_OF)

    def test_go_finding_is_in_application_scope(self) -> None:
        result = evaluate(
            report(
                ecosystem="Go",
                name="golang.org/x/example",
                version="1.0.0",
            ),
            manifest(),
            as_of=AS_OF,
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["summary"]["unexcepted_findings"], 1)

    def test_unknown_non_os_ecosystem_is_invalid(self) -> None:
        with self.assertRaisesRegex(EvaluationInputError, "neither"):
            evaluate(
                report(ecosystem="FuturePackageManager"),
                manifest(),
                as_of=AS_OF,
            )

    def test_json_input_must_not_be_a_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            regular = root / "report.json"
            regular.write_text('{"results": []}', encoding="utf-8")
            symlink = root / "report-link.json"
            symlink.symlink_to(regular)

            with self.assertRaisesRegex(EvaluationInputError, "symlink"):
                _read_json(symlink, "OSV report")


if __name__ == "__main__":
    unittest.main()
