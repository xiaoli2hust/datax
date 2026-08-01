#!/usr/bin/env python3
"""Container-local health probe for the egress attestation endpoint."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import UTC, datetime
from urllib.request import ProxyHandler, Request, build_opener
from uuid import UUID

URL = "http://127.0.0.1:17990/v1/attestation"
HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
NETNS_PATTERN = re.compile(r"^net:\[[0-9]+\]$")
MAX_POLICIES = 1_024


def compute_policy_set_hash(policies: dict[str, str]) -> str:
    ordered = [
        {"revision_id": revision_id, "policy_hash": policies[revision_id]}
        for revision_id in sorted(policies)
    ]
    payload = json.dumps(
        ordered,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(b"DXEGRESSPOLICYSETv1\n" + payload).hexdigest()


def main() -> int:
    try:
        request = Request(
            URL,
            method="GET",
            headers={"Accept": "application/json"},
        )
        with build_opener(ProxyHandler({})).open(request, timeout=2) as response:
            if response.status != 200:
                return 1
            body = response.read(64 * 1024 + 1)
        if len(body) > 64 * 1024:
            return 1
        document = json.loads(body)
        if set(document) != {
            "schema_version",
            "status",
            "policy_engine_version",
            "resolver_policy_version",
            "network_namespace_id",
            "policy_set_hash",
            "policies",
            "ruleset_hash",
            "applied_at",
            "checked_at",
        }:
            return 1
        if (
            document["schema_version"] != "1.0"
            or document["status"] != "VERIFIED"
            or document["policy_engine_version"] != "des-nftables-egress-v1"
            or document["resolver_policy_version"] != "des-system-dns-v1"
            or document["network_namespace_id"] != os.readlink("/proc/self/ns/net")
            or NETNS_PATTERN.fullmatch(document["network_namespace_id"]) is None
            or HASH_PATTERN.fullmatch(document["policy_set_hash"]) is None
            or HASH_PATTERN.fullmatch(document["ruleset_hash"]) is None
            or not isinstance(document["policies"], dict)
            or len(document["policies"]) > MAX_POLICIES
            or not isinstance(document["applied_at"], str)
            or not isinstance(document["checked_at"], str)
        ):
            return 1
        normalized_policies: dict[str, str] = {}
        for revision_id, policy_hash in document["policies"].items():
            if (
                not isinstance(revision_id, str)
                or str(UUID(revision_id)) != revision_id
                or not isinstance(policy_hash, str)
                or HASH_PATTERN.fullmatch(policy_hash) is None
            ):
                return 1
            normalized_policies[revision_id] = policy_hash
        if (
            list(normalized_policies) != sorted(normalized_policies)
            or compute_policy_set_hash(normalized_policies)
            != document["policy_set_hash"]
        ):
            return 1
        applied_at = datetime.fromisoformat(
            document["applied_at"].replace("Z", "+00:00")
        ).astimezone(UTC)
        checked_at = datetime.fromisoformat(
            document["checked_at"].replace("Z", "+00:00")
        ).astimezone(UTC)
        now = datetime.now(UTC)
        if (
            checked_at < applied_at
            or (now - checked_at).total_seconds() > 15
            or (checked_at - now).total_seconds() > 2
        ):
            return 1
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
