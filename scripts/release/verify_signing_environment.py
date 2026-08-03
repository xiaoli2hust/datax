"""Fail closed unless the Windows signing environment has reviewer protection.

The GitHub Actions ``environment`` key is only a name.  GitHub creates a missing
environment when a workflow references it, and that implicit environment has no
protection rules.  This verifier is deliberately small and uses only the public
Environment and deployment-branch-policy representations returned by GitHub's
REST API.  It is not a substitute for an isolated runner, non-exportable signing
keys, or final Windows E4 evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import sys
from pathlib import Path
from typing import Any

EXPECTED_ENVIRONMENT = "windows-candidate-signing"
MAX_REQUIRED_REVIEWERS = 6
MAX_DEPLOYMENT_BRANCH_POLICIES = 100
PROTECTION_HASH_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_SELECTOR_NAME_PATTERN = re.compile(r"[^\x00-\x1f\x7f]{1,255}\Z")


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


def _positive_integer(value: object, *, subject: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{subject} must be a positive numeric id")
    return value


def _deployment_branch_policy_flags(value: object) -> tuple[bool, bool]:
    if not isinstance(value, dict):
        raise TypeError("GitHub signing environment deployment branch policy is malformed")
    protected_branches = value.get("protected_branches")
    custom_branch_policies = value.get("custom_branch_policies")
    if (
        not isinstance(protected_branches, bool)
        or not isinstance(custom_branch_policies, bool)
    ):
        raise TypeError("GitHub signing environment deployment branch policy is malformed")
    if protected_branches == custom_branch_policies:
        raise ValueError(
            "GitHub signing environment deployment branch policy must enable "
            "exactly one branch selector"
        )
    return protected_branches, custom_branch_policies


def deployment_branch_selector_mode(document: object) -> str:
    """Return whether the caller must fetch GitHub's custom selector list.

    GitHub exposes protected-branch selection in the Environment response but
    exposes custom branch/tag patterns only through the separate
    ``deployment-branch-policies`` endpoint.  The workflow uses this small
    parser before issuing that second read; the full verifier still validates
    the Environment identity and protection rules afterwards.
    """

    if not isinstance(document, dict):
        raise TypeError("GitHub environment response must be a JSON object")
    policy = document.get("deployment_branch_policy")
    if policy is None:
        raise ValueError(
            "GitHub signing environment has no readable deployment branch policy"
        )
    _protected_branches, custom_branch_policies = _deployment_branch_policy_flags(policy)
    return "custom" if custom_branch_policies else "not-custom"


def _canonical_deployment_branch_selectors(document: object) -> list[dict[str, object]]:
    """Validate and normalize a complete custom branch/tag selector response.

    The workflow requests ``per_page=100``. More results are deliberately
    rejected instead of silently hashing only the first page. ``node_id`` is
    transport metadata; the positive REST id, exact selector name, and an
    optional documented branch/tag type form the protected semantic snapshot.
    """

    if not isinstance(document, dict):
        raise TypeError("GitHub deployment branch policy response must be a JSON object")
    if set(document) != {"total_count", "branch_policies"}:
        raise ValueError("GitHub deployment branch policy response has unsupported fields")
    total_count = document.get("total_count")
    if isinstance(total_count, bool) or not isinstance(total_count, int) or total_count < 0:
        raise ValueError("GitHub deployment branch policy total count is malformed")
    if total_count > MAX_DEPLOYMENT_BRANCH_POLICIES:
        raise ValueError(
            "GitHub deployment branch policy response exceeds the complete page limit"
        )
    if total_count == 0:
        raise ValueError("GitHub deployment branch policy has no custom selectors")
    policies = document.get("branch_policies")
    if not isinstance(policies, list) or len(policies) != total_count:
        raise ValueError("GitHub deployment branch policy response is incomplete")

    identifiers: set[int] = set()
    names: set[str] = set()
    canonical: list[dict[str, object]] = []
    for policy in policies:
        if not isinstance(policy, dict):
            raise TypeError("GitHub deployment branch policy entry must be an object")
        if set(policy) - {"id", "node_id", "name", "type"}:
            raise ValueError("GitHub deployment branch policy entry has unsupported fields")
        identifier = _positive_integer(
            policy.get("id"),
            subject="GitHub deployment branch policy identity",
        )
        name = policy.get("name")
        if not isinstance(name, str) or _SELECTOR_NAME_PATTERN.fullmatch(name) is None:
            raise ValueError("GitHub deployment branch policy selector is malformed")
        if identifier in identifiers or name in names:
            raise ValueError("GitHub deployment branch policy selectors are duplicated")
        raw_type = policy.get("type")
        if raw_type is not None and raw_type not in {"branch", "tag"}:
            raise ValueError("GitHub deployment branch policy selector type is malformed")
        if "node_id" in policy and (
            not isinstance(policy["node_id"], str) or not policy["node_id"]
        ):
            raise ValueError("GitHub deployment branch policy node identity is malformed")

        selector: dict[str, object] = {"id": identifier, "name": name}
        if raw_type is not None:
            selector["type"] = raw_type
        canonical.append(selector)
        identifiers.add(identifier)
        names.add(name)

    return sorted(
        canonical,
        key=lambda selector: (
            str(selector["name"]),
            str(selector.get("type", "")),
            int(selector["id"]),
        ),
    )


def _canonical_protection_snapshot(
    *,
    environment_id: int,
    expected_environment: str,
    rules: list[object],
    deployment_branch_policy: object,
    deployment_branch_policies: object | None,
) -> tuple[int, str]:
    """Return a non-secret, stable representation of the protection policy.

    Reviewer display names, login names, URLs, rule node IDs, and the response's
    other metadata are intentionally excluded.  The resulting SHA-256 is safe to
    pass between jobs, while still binding the review-policy semantics used by
    the signing gate.
    """

    reviewer_rule_count = 0
    wait_timer_rule_count = 0
    branch_policy_rule_count = 0
    canonical_rules: list[dict[str, object]] = []
    reviewer_count = 0

    for rule in rules:
        if not isinstance(rule, dict):
            raise TypeError("GitHub environment protection rule must be an object")
        rule_type = rule.get("type")
        if rule_type == "required_reviewers":
            reviewer_rule_count += 1
            if rule.get("prevent_self_review") is not True:
                raise ValueError(
                    "GitHub signing environment must prevent the workflow initiator "
                    "from self-review"
                )
            reviewers = rule.get("reviewers")
            if (
                not isinstance(reviewers, list)
                or not 1 <= len(reviewers) <= MAX_REQUIRED_REVIEWERS
            ):
                raise ValueError(
                    "GitHub signing environment must have one to six required reviewers"
                )
            identities = [_reviewer_identity(reviewer) for reviewer in reviewers]
            if len(set(identities)) != len(identities):
                raise ValueError(
                    "GitHub signing environment has duplicate required reviewers"
                )
            canonical_rules.append(
                {
                    "type": "required_reviewers",
                    "prevent_self_review": True,
                    "reviewers": [
                        {"type": reviewer_type, "id": identifier}
                        for reviewer_type, identifier in sorted(identities)
                    ],
                }
            )
            reviewer_count = len(identities)
            continue

        if rule_type == "wait_timer":
            wait_timer_rule_count += 1
            wait_timer = rule.get("wait_timer")
            if (
                isinstance(wait_timer, bool)
                or not isinstance(wait_timer, int)
                or wait_timer < 0
            ):
                raise ValueError("GitHub signing environment wait timer is malformed")
            canonical_rules.append(
                {"type": "wait_timer", "wait_timer": wait_timer}
            )
            continue

        if rule_type == "branch_policy":
            branch_policy_rule_count += 1
            canonical_rules.append({"type": "branch_policy"})
            continue

        raise ValueError("GitHub signing environment has an unsupported protection rule")

    if reviewer_rule_count != 1:
        raise ValueError(
            "GitHub signing environment must define exactly one required-reviewers rule"
        )
    if wait_timer_rule_count > 1:
        raise ValueError("GitHub signing environment has duplicate wait-timer rules")
    if branch_policy_rule_count > 1:
        raise ValueError("GitHub signing environment has duplicate branch-policy rules")

    if deployment_branch_policy is None:
        raise ValueError(
            "GitHub signing environment has no readable deployment branch policy"
        )
    protected_branches, custom_branch_policies = _deployment_branch_policy_flags(
        deployment_branch_policy
    )
    if branch_policy_rule_count != 1:
        raise ValueError(
            "GitHub signing environment deployment branch policy and "
            "branch-policy rule are inconsistent"
        )
    canonical_branch_policy: dict[str, bool] = {
        "protected_branches": protected_branches,
        "custom_branch_policies": custom_branch_policies,
    }
    if custom_branch_policies:
        if deployment_branch_policies is None:
            raise ValueError(
                "GitHub signing environment custom branch selectors are unavailable"
            )
        canonical_branch_selectors: list[dict[str, object]] | None = (
            _canonical_deployment_branch_selectors(deployment_branch_policies)
        )
    else:
        if deployment_branch_policies is not None:
            raise ValueError(
                "GitHub signing environment protected-branch policy has unexpected "
                "custom selectors"
            )
        canonical_branch_selectors = None

    # Identity is included in the preflight hash as a defense in depth measure;
    # the caller also compares it directly before importing the PFX.
    canonical_document = {
        "schema_version": "1.0",
        "environment": expected_environment,
        "environment_id": environment_id,
        "protection_rules": sorted(
            canonical_rules,
            key=lambda rule: json.dumps(rule, sort_keys=True, separators=(",", ":")),
        ),
        "deployment_branch_policy": canonical_branch_policy,
        "deployment_branch_selectors": canonical_branch_selectors,
    }
    canonical_json = json.dumps(
        canonical_document,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    protection_sha256 = hashlib.sha256(canonical_json.encode("ascii")).hexdigest()
    return reviewer_count, protection_sha256


def validate_signing_environment(
    document: object,
    *,
    expected_environment: str = EXPECTED_ENVIRONMENT,
    expected_environment_id: int | None = None,
    expected_protection_sha256: str | None = None,
    deployment_branch_policies: object | None = None,
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

    environment_id = _positive_integer(
        document.get("id"),
        subject="GitHub signing environment immutable identity",
    )
    rules = document.get("protection_rules")
    if not isinstance(rules, list):
        raise TypeError("GitHub environment has no readable protection rules")
    reviewer_count, protection_sha256 = _canonical_protection_snapshot(
        environment_id=environment_id,
        expected_environment=expected_environment,
        rules=rules,
        deployment_branch_policy=document.get("deployment_branch_policy"),
        deployment_branch_policies=deployment_branch_policies,
    )

    if (expected_environment_id is None) != (expected_protection_sha256 is None):
        raise ValueError(
            "GitHub signing environment snapshot requires both identity and protection hash"
        )
    if expected_environment_id is not None:
        expected_id = _positive_integer(
            expected_environment_id,
            subject="expected GitHub signing environment immutable identity",
        )
        if environment_id != expected_id:
            raise ValueError(
                "GitHub signing environment immutable identity changed since preflight"
            )
        if (
            not isinstance(expected_protection_sha256, str)
            or PROTECTION_HASH_PATTERN.fullmatch(expected_protection_sha256) is None
        ):
            raise ValueError("expected signing-environment protection hash is malformed")
        if not hmac.compare_digest(protection_sha256, expected_protection_sha256):
            raise ValueError(
                "GitHub signing environment protection changed since preflight"
            )

    return {
        "ready": True,
        "code": "WINDOWS_SIGNING_ENVIRONMENT_PROTECTION_VALID",
        "environment": expected_environment,
        "environment_id": environment_id,
        "protection_sha256": protection_sha256,
        "required_reviewer_count": reviewer_count,
    }


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate the GitHub approval gate used by the Windows signing job."
    )
    parser.add_argument("--environment-json", type=Path, required=True)
    parser.add_argument("--deployment-branch-policies-json", type=Path)
    parser.add_argument("--expected-environment", default=EXPECTED_ENVIRONMENT)
    parser.add_argument("--expected-environment-id", type=int)
    parser.add_argument("--expected-protection-sha256")
    parser.add_argument(
        "--selector-mode",
        action="store_true",
        help="print whether the Environment requires the custom selector endpoint",
    )
    return parser.parse_args()


def _read_json_document(path: Path) -> object:
    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicate_object_pairs,
    )


def main() -> int:
    arguments = _arguments()
    try:
        document = _read_json_document(arguments.environment_json)
        if getattr(arguments, "selector_mode", False):
            print(deployment_branch_selector_mode(document))
            return 0
        branch_policy_path = getattr(arguments, "deployment_branch_policies_json", None)
        deployment_branch_policies = (
            _read_json_document(branch_policy_path)
            if branch_policy_path is not None
            else None
        )
        result = validate_signing_environment(
            document,
            expected_environment=arguments.expected_environment,
            expected_environment_id=getattr(arguments, "expected_environment_id", None),
            expected_protection_sha256=getattr(
                arguments,
                "expected_protection_sha256",
                None,
            ),
            deployment_branch_policies=deployment_branch_policies,
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
