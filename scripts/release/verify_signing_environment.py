"""Fail closed unless the Windows signing environment has reviewer protection.

The GitHub Actions ``environment`` key is only a name.  GitHub creates a missing
environment when a workflow references it, and that implicit environment has no
protection rules.  This verifier is deliberately small and uses only the public
environment representation returned by GitHub's REST API.  It is not a substitute
for an isolated runner, non-exportable signing keys, or final Windows E4 evidence.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

EXPECTED_ENVIRONMENT = "windows-candidate-signing"
MAX_REQUIRED_REVIEWERS = 6


def _reject_duplicate_object_pairs(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate JSON object key: {key}")
        document[key] = value
    return document


def _reviewer_identity(reviewer: object) -> tuple[str, int]:
    if not isinstance(reviewer, dict):
        raise TypeError("required reviewer entry must be an object")
    reviewer_type = reviewer.get("type")
    reviewer_detail = reviewer.get("reviewer")
    if reviewer_type not in {"User", "Team"} or not isinstance(reviewer_detail, dict):
        raise ValueError("required reviewer identity is malformed")
    identifier = reviewer_detail.get("id")
    if isinstance(identifier, bool) or not isinstance(identifier, int) or identifier < 1:
        raise ValueError("required reviewer identity must have a positive numeric id")
    return reviewer_type, identifier


def validate_signing_environment(
    document: object,
    *,
    expected_environment: str = EXPECTED_ENVIRONMENT,
) -> dict[str, object]:
    """Validate the minimum reviewer gate required before any signing step.

    The release workflow independently constrains candidate source identity to
    ``main`` or an exact semver tag.  This verifier intentionally concerns only
    the environment approval rule, which is the control GitHub would otherwise
    omit when it implicitly creates a missing environment.
    """

    if not isinstance(document, dict):
        raise TypeError("GitHub environment response must be a JSON object")
    if document.get("name") != expected_environment:
        raise ValueError("GitHub environment name does not match the signing gate")

    rules = document.get("protection_rules")
    if not isinstance(rules, list):
        raise TypeError("GitHub environment has no readable protection rules")
    reviewer_rules = [
        rule
        for rule in rules
        if isinstance(rule, dict) and rule.get("type") == "required_reviewers"
    ]
    if len(reviewer_rules) != 1:
        raise ValueError(
            "GitHub signing environment must define exactly one required-reviewers rule"
        )
    rule = reviewer_rules[0]
    if rule.get("prevent_self_review") is not True:
        raise ValueError(
            "GitHub signing environment must prevent the workflow initiator from self-review"
        )
    reviewers = rule.get("reviewers")
    if not isinstance(reviewers, list) or not 1 <= len(reviewers) <= MAX_REQUIRED_REVIEWERS:
        raise ValueError(
            "GitHub signing environment must have one to six required reviewers"
        )
    identities = [_reviewer_identity(reviewer) for reviewer in reviewers]
    if len(set(identities)) != len(identities):
        raise ValueError("GitHub signing environment has duplicate required reviewers")

    return {
        "ready": True,
        "code": "WINDOWS_SIGNING_ENVIRONMENT_PROTECTION_VALID",
        "environment": expected_environment,
        "required_reviewer_count": len(reviewers),
    }


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate the GitHub approval gate used by the Windows signing job."
    )
    parser.add_argument("--environment-json", type=Path, required=True)
    parser.add_argument("--expected-environment", default=EXPECTED_ENVIRONMENT)
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    try:
        document = json.loads(
            arguments.environment_json.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_object_pairs,
        )
        result = validate_signing_environment(
            document,
            expected_environment=arguments.expected_environment,
        )
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as exc:
        print(
            json.dumps(
                {
                    "ready": False,
                    "code": "WINDOWS_SIGNING_ENVIRONMENT_PROTECTION_INVALID",
                    "detail": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
