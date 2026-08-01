from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

from scripts.release.verify_signing_environment import (
    EXPECTED_ENVIRONMENT,
    main,
    validate_signing_environment,
)


def _protected_environment() -> dict[str, object]:
    return {
        "name": EXPECTED_ENVIRONMENT,
        "protection_rules": [
            {
                "type": "required_reviewers",
                "prevent_self_review": True,
                "reviewers": [
                    {"type": "User", "reviewer": {"id": 42, "login": "release-qa"}}
                ],
            }
        ],
    }


class SigningEnvironmentVerifierTests(unittest.TestCase):
    def test_accepts_a_distinct_required_reviewer(self) -> None:
        result = validate_signing_environment(_protected_environment())

        self.assertTrue(result["ready"])
        self.assertEqual(
            result["code"], "WINDOWS_SIGNING_ENVIRONMENT_PROTECTION_VALID"
        )
        self.assertEqual(result["required_reviewer_count"], 1)

    def test_rejects_missing_or_self_approvable_reviewer_gate(self) -> None:
        cases = (
            (
                "missing",
                {"name": EXPECTED_ENVIRONMENT, "protection_rules": []},
                "exactly one required-reviewers",
            ),
            (
                "self-review",
                {
                    "name": EXPECTED_ENVIRONMENT,
                    "protection_rules": [
                        {
                            "type": "required_reviewers",
                            "prevent_self_review": False,
                            "reviewers": [
                                {"type": "User", "reviewer": {"id": 42}}
                            ],
                        }
                    ],
                },
                "prevent the workflow initiator",
            ),
            (
                "empty",
                {
                    "name": EXPECTED_ENVIRONMENT,
                    "protection_rules": [
                        {
                            "type": "required_reviewers",
                            "prevent_self_review": True,
                            "reviewers": [],
                        }
                    ],
                },
                "one to six",
            ),
        )
        for name, document, message in cases:
            with self.subTest(case=name), self.assertRaisesRegex(ValueError, message):
                validate_signing_environment(document)

    def test_rejects_wrong_environment_and_duplicate_or_malformed_reviewers(self) -> None:
        wrong_name = _protected_environment()
        wrong_name["name"] = "other"
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate_signing_environment(wrong_name)

        duplicate = _protected_environment()
        duplicate_rule = duplicate["protection_rules"][0]  # type: ignore[index]
        duplicate_rule["reviewers"].append(  # type: ignore[index]
            {"type": "User", "reviewer": {"id": 42}}
        )
        with self.assertRaisesRegex(ValueError, "duplicate"):
            validate_signing_environment(duplicate)

        malformed = _protected_environment()
        malformed_rule = malformed["protection_rules"][0]  # type: ignore[index]
        malformed_rule["reviewers"] = [  # type: ignore[index]
            {"type": "Organization", "reviewer": {"id": 7}}
        ]
        with self.assertRaisesRegex(ValueError, "malformed"):
            validate_signing_environment(malformed)

    def test_cli_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "environment.json"
            path.write_text(
                '{"name":"windows-candidate-signing","name":"other"}\n',
                encoding="utf-8",
            )
            stderr = io.StringIO()
            with (
                mock.patch(
                    "scripts.release.verify_signing_environment._arguments",
                    return_value=type(
                        "Arguments",
                        (),
                        {
                            "environment_json": path,
                            "expected_environment": EXPECTED_ENVIRONMENT,
                        },
                    )(),
                ),
                redirect_stderr(stderr),
            ):
                self.assertEqual(main(), 1)
            result = json.loads(stderr.getvalue())
            self.assertEqual(
                result["code"], "WINDOWS_SIGNING_ENVIRONMENT_PROTECTION_INVALID"
            )
            self.assertFalse(result["ready"])


if __name__ == "__main__":
    unittest.main()
