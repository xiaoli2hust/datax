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
        "id": 7100,
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


def _protected_environment_with_branch_policy(
    *,
    protected_branches: bool = True,
) -> dict[str, object]:
    document = _protected_environment()
    document["protection_rules"].append(  # type: ignore[index]
        {"type": "branch_policy"}
    )
    document["deployment_branch_policy"] = {
        "protected_branches": protected_branches,
        "custom_branch_policies": not protected_branches,
    }
    return document


class SigningEnvironmentVerifierTests(unittest.TestCase):
    def test_accepts_a_distinct_required_reviewer(self) -> None:
        result = validate_signing_environment(_protected_environment())

        self.assertTrue(result["ready"])
        self.assertEqual(
            result["code"], "WINDOWS_SIGNING_ENVIRONMENT_PROTECTION_VALID"
        )
        self.assertEqual(result["required_reviewer_count"], 1)
        self.assertEqual(result["environment_id"], 7100)
        self.assertRegex(result["protection_sha256"], r"^[0-9a-f]{64}$")
        self.assertNotIn("reviewers", result)
        self.assertNotIn("release-qa", json.dumps(result, sort_keys=True))

    def test_rejects_missing_or_self_approvable_reviewer_gate(self) -> None:
        cases = (
            (
                "missing",
                {
                    "id": 7100,
                    "name": EXPECTED_ENVIRONMENT,
                    "protection_rules": [],
                },
                "exactly one required-reviewers",
            ),
            (
                "self-review",
                {
                    "id": 7100,
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
                    "id": 7100,
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

    def test_snapshot_binds_immutable_identity_and_canonical_protection(self) -> None:
        preflight = validate_signing_environment(_protected_environment())
        expected_id = preflight["environment_id"]
        expected_hash = preflight["protection_sha256"]
        self.assertIsInstance(expected_id, int)
        self.assertIsInstance(expected_hash, str)

        current = _protected_environment()
        accepted = validate_signing_environment(
            current,
            expected_environment_id=expected_id,
            expected_protection_sha256=expected_hash,
        )
        self.assertEqual(accepted["protection_sha256"], expected_hash)

        recreated = _protected_environment()
        recreated["id"] = 7101
        with self.assertRaisesRegex(ValueError, "identity changed since preflight"):
            validate_signing_environment(
                recreated,
                expected_environment_id=expected_id,
                expected_protection_sha256=expected_hash,
            )

        changed_reviewer = _protected_environment()
        changed_rule = changed_reviewer["protection_rules"][0]  # type: ignore[index]
        changed_rule["reviewers"] = [  # type: ignore[index]
            {"type": "User", "reviewer": {"id": 99, "login": "different"}}
        ]
        with self.assertRaisesRegex(ValueError, "protection changed since preflight"):
            validate_signing_environment(
                changed_reviewer,
                expected_environment_id=expected_id,
                expected_protection_sha256=expected_hash,
            )

    def test_snapshot_hash_includes_supported_wait_timer_and_branch_policy(self) -> None:
        baseline = _protected_environment()
        with_wait = _protected_environment()
        with_wait["protection_rules"].append(  # type: ignore[index]
            {"type": "wait_timer", "wait_timer": 15}
        )

        baseline_result = validate_signing_environment(baseline)
        with_wait_result = validate_signing_environment(with_wait)
        self.assertNotEqual(
            baseline_result["protection_sha256"],
            with_wait_result["protection_sha256"],
        )

        with_branch_policy = _protected_environment_with_branch_policy()
        with_branch_policy_result = validate_signing_environment(with_branch_policy)
        self.assertNotEqual(
            baseline_result["protection_sha256"],
            with_branch_policy_result["protection_sha256"],
        )

        preflight = validate_signing_environment(with_branch_policy)
        changed_selector = _protected_environment_with_branch_policy(
            protected_branches=False
        )
        with self.assertRaisesRegex(ValueError, "protection changed since preflight"):
            validate_signing_environment(
                changed_selector,
                expected_environment_id=preflight["environment_id"],  # type: ignore[arg-type]
                expected_protection_sha256=preflight["protection_sha256"],  # type: ignore[arg-type]
            )

    def test_rejects_inconsistent_or_malformed_branch_policy(self) -> None:
        missing_readable_policy = _protected_environment()
        missing_readable_policy["protection_rules"].append(  # type: ignore[index]
            {"type": "branch_policy"}
        )
        with self.assertRaisesRegex(ValueError, "has no readable"):
            validate_signing_environment(missing_readable_policy)

        missing_rule = _protected_environment()
        missing_rule["deployment_branch_policy"] = {
            "protected_branches": True,
            "custom_branch_policies": False,
        }
        with self.assertRaisesRegex(ValueError, "are inconsistent"):
            validate_signing_environment(missing_rule)

        duplicate_rule = _protected_environment_with_branch_policy()
        duplicate_rule["protection_rules"].append(  # type: ignore[index]
            {"type": "branch_policy"}
        )
        with self.assertRaisesRegex(ValueError, "duplicate branch-policy"):
            validate_signing_environment(duplicate_rule)

        for name, policy in (
            (
                "both-disabled",
                {
                    "protected_branches": False,
                    "custom_branch_policies": False,
                },
            ),
            (
                "both-enabled",
                {
                    "protected_branches": True,
                    "custom_branch_policies": True,
                },
            ),
            (
                "wrong-type",
                {
                    "protected_branches": "true",
                    "custom_branch_policies": False,
                },
            ),
        ):
            malformed = _protected_environment_with_branch_policy()
            malformed["deployment_branch_policy"] = policy
            with self.subTest(case=name), self.assertRaisesRegex(
                ValueError,
                "must enable exactly one|is malformed",
            ):
                validate_signing_environment(malformed)

    def test_rejects_missing_identity_unknown_rule_and_partial_snapshot(self) -> None:
        missing_identity = _protected_environment()
        missing_identity.pop("id")
        with self.assertRaisesRegex(ValueError, "immutable identity"):
            validate_signing_environment(missing_identity)

        unknown_rule = _protected_environment()
        unknown_rule["protection_rules"].append(  # type: ignore[index]
            {"type": "custom_protection"}
        )
        with self.assertRaisesRegex(ValueError, "unsupported protection rule"):
            validate_signing_environment(unknown_rule)

        with self.assertRaisesRegex(ValueError, "requires both identity"):
            validate_signing_environment(
                _protected_environment(),
                expected_environment_id=7100,
            )

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
