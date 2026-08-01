from __future__ import annotations

import http.client
import ipaddress
import json
import threading
import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from guard import (
    POLICY_ENGINE_VERSION,
    RESOLVER_POLICY_VERSION,
    AttestationServer,
    AttestationState,
    EgressRule,
    GuardController,
    GuardError,
    _without_expiry_counters,
    lease_is_allowed,
    nft_batch,
    normalize_lease_request,
    normalize_policy_rows,
    parse_control_route,
)


def policy_row(**updates: object) -> dict[str, object]:
    row: dict[str, object] = {
        "revision_id": "11111111-1111-4111-8111-111111111111",
        "policy_hash": "a" * 64,
        "resolver_policy_version": RESOLVER_POLICY_VERSION,
        "egress_policy_version": POLICY_ENGINE_VERSION,
        "allowed_cidrs": ["10.20.0.0/16", "2001:db8:1234::/48"],
        "allowed_ports": [3306, 5432],
    }
    row.update(updates)
    return row


def lease_request(**updates: object) -> dict[str, object]:
    request: dict[str, object] = {
        "schema_version": "1.0",
        "revision_id": "11111111-1111-4111-8111-111111111111",
        "policy_hash": "a" * 64,
        "selected_ip": "10.20.3.4",
        "port": 5432,
    }
    request.update(updates)
    return request


class PolicyValidationTests(unittest.TestCase):
    def test_builds_deterministic_cross_product_and_hash(self) -> None:
        snapshot = normalize_policy_rows([policy_row()])
        self.assertEqual(len(snapshot.rules), 4)
        self.assertEqual(
            snapshot.policies, {"11111111-1111-4111-8111-111111111111": "a" * 64}
        )
        self.assertEqual(
            snapshot.policy_set_hash,
            "5c386081d44476af163c706358f92a675ac9dfd568f18da4f55fe80464f6b612",
        )
        self.assertEqual(snapshot, normalize_policy_rows([policy_row()]))

    def test_empty_active_policy_set_is_valid_default_deny(self) -> None:
        snapshot = normalize_policy_rows([])
        self.assertEqual(snapshot.policies, {})
        self.assertEqual(snapshot.rules, ())
        self.assertEqual(
            snapshot.policy_set_hash,
            "362b05d497f9eab0708a408aadeafab04164d83ae3189b19801c687e7d45115e",
        )

    def test_rejects_unknown_fields_versions_and_unsafe_networks(self) -> None:
        cases = [
            policy_row(extra="unexpected"),
            policy_row(egress_policy_version="operator-claimed-verified"),
            policy_row(resolver_policy_version="UNVERIFIED"),
            policy_row(allowed_cidrs=["0.0.0.0/0"]),
            policy_row(allowed_cidrs=["169.254.0.0/16"]),
            policy_row(allowed_cidrs=["10.20.1.1/16"]),
        ]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(GuardError):
                normalize_policy_rows([value])

    def test_rejects_duplicate_or_unsorted_ports_and_excessive_rules(self) -> None:
        for ports in ([5432, 3306], [5432, 5432], [0], [65_536]):
            with self.subTest(ports=ports), self.assertRaises(GuardError):
                normalize_policy_rows([policy_row(allowed_ports=ports)])
        with self.assertRaises(GuardError):
            normalize_policy_rows(
                [
                    policy_row(
                        allowed_cidrs=[
                            f"10.{second}.{third}.0/24"
                            for second in range(16)
                            for third in range(4)
                        ],
                        allowed_ports=list(range(1, 33)),
                    ),
                    policy_row(
                        revision_id="22222222-2222-4222-8222-222222222222",
                        policy_hash="b" * 64,
                        allowed_cidrs=[
                            f"172.{second}.{third}.0/24"
                            for second in range(16, 32)
                            for third in range(4)
                        ],
                        allowed_ports=list(range(1, 33)),
                    ),
                    policy_row(
                        revision_id="33333333-3333-4333-8333-333333333333",
                        policy_hash="c" * 64,
                        allowed_cidrs=[f"192.168.{third}.0/24" for third in range(64)],
                        allowed_ports=list(range(1, 33)),
                    ),
                ]
            )


class NftContractTests(unittest.TestCase):
    def test_batch_has_drop_base_dns_control_and_exact_endpoint_pairs(self) -> None:
        rules = (
            EgressRule(
                network_version=4,
                network_address=int(ipaddress.ip_address("10.20.3.4")),
                prefix_length=32,
                port=3306,
                revision_id="11111111-1111-4111-8111-111111111111",
                policy_hash="a" * 64,
                cidr="10.20.3.4/32",
                timeout_seconds=15,
            ),
            EgressRule(
                network_version=6,
                network_address=int(ipaddress.ip_address("2001:db8:1234::9")),
                prefix_length=128,
                port=5432,
                revision_id="11111111-1111-4111-8111-111111111111",
                policy_hash="a" * 64,
                cidr="2001:db8:1234::9/128",
                timeout_seconds=9,
            ),
        )
        batch = nft_batch(
            ipaddress.ip_network("172.29.0.0/16"),
            rules,
            table_exists=True,
        )
        self.assertTrue(batch.startswith("delete table inet des_egress\n"))
        self.assertIn("policy drop", batch)
        self.assertIn("ip daddr 127.0.0.11 udp dport 53 accept", batch)
        self.assertIn("ip daddr 172.29.0.0/16 accept", batch)
        self.assertIn("flags timeout", batch)
        self.assertNotIn("flags interval", batch)
        self.assertIn("10.20.3.4 . 3306 timeout 15s", batch)
        self.assertIn("2001:db8:1234::9 . 5432 timeout 9s", batch)
        self.assertNotIn("10.20.0.0/16", batch)
        self.assertIn(
            "ct state new,established ip daddr . tcp dport @allowed_ipv4 accept",
            batch,
        )
        self.assertNotIn("policy accept", batch)

    def test_rejects_policy_cidr_as_a_kernel_allow_rule(self) -> None:
        snapshot = normalize_policy_rows([policy_row()])
        with self.assertRaisesRegex(GuardError, "NFT_LEASE_RULE_INVALID"):
            nft_batch(
                ipaddress.ip_network("172.29.0.0/16"),
                snapshot.rules,
                table_exists=False,
            )

    def test_empty_policy_batch_has_no_dynamic_allow_set(self) -> None:
        batch = nft_batch(
            ipaddress.ip_network("172.29.0.0/16"),
            (),
            table_exists=False,
        )
        self.assertNotIn("allowed_ipv4", batch)
        self.assertNotIn("allowed_ipv6", batch)
        self.assertNotIn("ct state new,established", batch)

    def test_ruleset_hash_input_ignores_only_runtime_expiry_countdown(self) -> None:
        before = {
            "nftables": [
                {"set": {"name": "allowed_ipv4", "expires": 14_500}},
                {"rule": {"expr": [{"match": {"right": 3306}}]}},
            ]
        }
        after = {
            "nftables": [
                {"set": {"name": "allowed_ipv4", "expires": 9_100}},
                {"rule": {"expr": [{"match": {"right": 3306}}]}},
            ]
        }
        self.assertEqual(
            _without_expiry_counters(before),
            _without_expiry_counters(after),
        )
        after["nftables"][1]["rule"]["expr"][0]["match"]["right"] = 5432
        self.assertNotEqual(
            _without_expiry_counters(before),
            _without_expiry_counters(after),
        )

    def test_control_route_is_derived_from_default_interface(self) -> None:
        routes = """\
Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
eth0 00000000 01001DAC 0003 0 0 0 00000000 0 0 0
eth0 00001DAC 00000000 0001 0 0 0 0000FFFF 0 0 0
"""
        network = parse_control_route(
            routes,
            interface_addresses={"eth0": ipaddress.ip_address("172.29.0.5")},
        )
        self.assertEqual(network, ipaddress.ip_network("172.29.0.0/16"))


class AttestationTests(unittest.TestCase):
    def test_stale_attestation_blocks_without_claiming_verified(self) -> None:
        state = AttestationState("net:[4026532001]")
        snapshot = normalize_policy_rows([policy_row()])
        checked = datetime.now(UTC) - timedelta(seconds=30)
        state.verified(snapshot, "b" * 64, checked)
        document = state.document(datetime.now(UTC))
        self.assertEqual(document["status"], "BLOCKED")
        self.assertEqual(document["policy_engine_version"], POLICY_ENGINE_VERSION)


class LeaseValidationTests(unittest.TestCase):
    def test_requires_canonical_exact_selected_ip_and_active_policy_scope(self) -> None:
        snapshot = normalize_policy_rows([policy_row()])
        normalized = normalize_lease_request(lease_request())
        self.assertEqual(
            normalized,
            (
                "11111111-1111-4111-8111-111111111111",
                "a" * 64,
                "10.20.3.4",
                5432,
            ),
        )
        self.assertTrue(
            lease_is_allowed(
                snapshot,
                revision_id=normalized[0],
                policy_hash=normalized[1],
                selected_ip=normalized[2],
                port=normalized[3],
            )
        )
        self.assertFalse(
            lease_is_allowed(
                snapshot,
                revision_id=normalized[0],
                policy_hash=normalized[1],
                selected_ip="10.21.0.1",
                port=normalized[3],
            )
        )

    def test_rejects_unknown_fields_hostnames_and_noncanonical_addresses(self) -> None:
        for request in (
            lease_request(extra=True),
            lease_request(selected_ip="db.example.com"),
            lease_request(selected_ip="2001:0db8:1234::9"),
            lease_request(selected_ip="127.0.0.1"),
            lease_request(port=True),
        ):
            with self.subTest(request=request), self.assertRaises(GuardError):
                normalize_lease_request(request)


class _FakeNftables:
    def __init__(self) -> None:
        self.current_hash = "1" * 64
        self.applied: list[tuple[object, ...]] = []

    def ruleset_hash(self) -> str:
        return self.current_hash

    def apply(
        self,
        _control_network: ipaddress.IPv4Network,
        rules: object,
    ) -> str:
        normalized = tuple(rules)
        self.applied.append(normalized)
        self.current_hash = ("2" if normalized else "3") * 64
        return self.current_hash


class _FakePolicySource:
    def __init__(self, snapshot=None) -> None:
        self.loads = 0
        self.snapshot = snapshot or normalize_policy_rows([policy_row()])
        self.failure: GuardError | None = None

    def load(self):
        self.loads += 1
        if self.failure is not None:
            raise self.failure
        return self.snapshot


class ControllerFailClosedTests(unittest.TestCase):
    def test_ruleset_drift_latches_base_deny_until_restart(self) -> None:
        nftables = _FakeNftables()
        policies = _FakePolicySource()
        state = AttestationState("net:[4026532001]")
        controller = GuardController(
            control_network=ipaddress.ip_network("172.29.0.0/16"),
            nftables=nftables,
            policies=policies,
            state=state,
        )
        controller.refresh_once()
        self.assertEqual(state.document()["status"], "VERIFIED")
        self.assertEqual(policies.loads, 1)

        nftables.current_hash = "f" * 64
        controller.refresh_once()
        self.assertEqual(state.document()["status"], "BLOCKED")
        self.assertEqual(nftables.applied[-1], ())

        controller.refresh_once()
        self.assertEqual(state.document()["status"], "BLOCKED")
        self.assertEqual(policies.loads, 1)

    def test_lease_create_renew_release_uses_generated_token_and_exact_ip(self) -> None:
        nftables = _FakeNftables()
        policies = _FakePolicySource()
        state = AttestationState("net:[4026532001]")
        controller = GuardController(
            control_network=ipaddress.ip_network("172.29.0.0/16"),
            nftables=nftables,
            policies=policies,
            state=state,
        )
        controller.refresh_once()
        with (
            patch("guard.secrets.token_bytes", return_value=b"\x01" * 32),
            patch(
                "guard.uuid4",
                return_value=__import__("uuid").UUID(
                    "44444444-4444-4444-8444-444444444444"
                ),
            ),
        ):
            granted = controller.create_lease(lease_request())
        self.assertEqual(
            set(granted),
            {
                "schema_version",
                "status",
                "lease_id",
                "bearer_token",
                "revision_id",
                "policy_hash",
                "selected_ip",
                "port",
                "expires_at",
                "renew_after_seconds",
                "kernel_timeout_seconds",
                "ruleset_hash",
            },
        )
        self.assertEqual(granted["status"], "GRANTED")
        self.assertEqual(granted["lease_id"], "44444444-4444-4444-8444-444444444444")
        self.assertEqual(len(granted["bearer_token"]), 43)
        applied_rule = nftables.applied[-1][0]
        self.assertEqual(applied_rule.cidr, "10.20.3.4/32")
        self.assertEqual(applied_rule.port, 5432)
        self.assertEqual(applied_rule.timeout_seconds, 15)
        self.assertNotIn("bearer_token", state.document())

        renewed = controller.renew_lease(
            granted["lease_id"],
            granted["bearer_token"],
        )
        self.assertEqual(renewed["status"], "RENEWED")
        self.assertNotIn("bearer_token", renewed)
        applied_count = len(nftables.applied)
        with self.assertRaisesRegex(GuardError, "LEASE_AUTH_INVALID"):
            controller.renew_lease(granted["lease_id"], "A" * 43)
        self.assertEqual(len(nftables.applied), applied_count)

        controller.release_lease(
            granted["lease_id"],
            granted["bearer_token"],
        )
        self.assertEqual(nftables.applied[-1], ())

    def test_policy_revocation_and_database_failure_clear_all_leases(self) -> None:
        nftables = _FakeNftables()
        policies = _FakePolicySource()
        state = AttestationState("net:[4026532001]")
        controller = GuardController(
            control_network=ipaddress.ip_network("172.29.0.0/16"),
            nftables=nftables,
            policies=policies,
            state=state,
        )
        controller.refresh_once()
        granted = controller.create_lease(lease_request())
        self.assertTrue(nftables.applied[-1])

        policies.snapshot = normalize_policy_rows([])
        controller.refresh_once()
        self.assertEqual(nftables.applied[-1], ())
        self.assertEqual(state.document()["status"], "BLOCKED")
        with self.assertRaisesRegex(GuardError, "LEASE_NOT_FOUND"):
            controller.renew_lease(granted["lease_id"], granted["bearer_token"])

        controller.refresh_once()
        self.assertEqual(state.document()["status"], "VERIFIED")
        policies.failure = GuardError("POLICY_DATABASE_UNAVAILABLE")
        controller.refresh_once()
        self.assertEqual(nftables.applied[-1], ())
        self.assertEqual(state.document()["status"], "BLOCKED")

    def test_control_network_endpoint_is_never_admitted_as_a_lease(self) -> None:
        nftables = _FakeNftables()
        policies = _FakePolicySource(
            normalize_policy_rows(
                [
                    policy_row(
                        allowed_cidrs=["172.29.0.0/16"],
                        allowed_ports=[5432],
                    )
                ]
            )
        )
        state = AttestationState("net:[4026532001]")
        controller = GuardController(
            control_network=ipaddress.ip_network("172.29.0.0/16"),
            nftables=nftables,
            policies=policies,
            state=state,
        )
        controller.refresh_once()

        with self.assertRaisesRegex(GuardError, "LEASE_POLICY_NOT_ACTIVE"):
            controller.create_lease(lease_request(selected_ip="172.29.0.10", port=5432))

        self.assertEqual(nftables.applied[-1], ())
        self.assertEqual(state.document()["status"], "VERIFIED")


class LeaseHttpContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.nftables = _FakeNftables()
        self.policies = _FakePolicySource()
        self.state = AttestationState("net:[4026532001]")
        self.controller = GuardController(
            control_network=ipaddress.ip_network("172.29.0.0/16"),
            nftables=self.nftables,
            policies=self.policies,
            state=self.state,
        )
        self.controller.refresh_once()
        self.server = AttestationServer(
            ("127.0.0.1", 0),
            self.state,
            self.controller,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, object] | None]:
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            self.server.server_address[1],
            timeout=2,
        )
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            payload = response.read()
        finally:
            connection.close()
        return response.status, json.loads(payload) if payload else None

    def test_create_renew_release_and_error_contract(self) -> None:
        body = json.dumps(lease_request(), separators=(",", ":")).encode()
        status, granted = self.request(
            "POST",
            "/v1/leases",
            body=body,
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 201)
        self.assertIsNotNone(granted)
        lease_id = granted["lease_id"]
        token = granted["bearer_token"]

        status, renewed = self.request(
            "PUT",
            f"/v1/leases/{lease_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(renewed["status"], "RENEWED")
        self.assertNotIn("bearer_token", renewed)

        status, error = self.request(
            "PUT",
            f"/v1/leases/{lease_id}",
            headers={"Authorization": f"Bearer {'A' * 43}"},
        )
        self.assertEqual((status, error), (401, {"code": "LEASE_AUTH_INVALID"}))

        status, payload = self.request(
            "DELETE",
            f"/v1/leases/{lease_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual((status, payload), (204, None))

    def test_post_reads_one_strict_json_body_and_rejects_policy_escape(self) -> None:
        request = lease_request(selected_ip="10.21.0.1")
        status, error = self.request(
            "POST",
            "/v1/leases",
            body=json.dumps(request).encode(),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual((status, error), (409, {"code": "LEASE_POLICY_NOT_ACTIVE"}))

        invalid_revision = lease_request(revision_id="NOT-A-UUID")
        status, error = self.request(
            "POST",
            "/v1/leases",
            body=json.dumps(invalid_revision).encode(),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual((status, error), (400, {"code": "LEASE_REQUEST_INVALID"}))

        status, error = self.request(
            "POST",
            "/v1/leases",
            body=b"{}",
            headers={"Content-Type": "text/plain"},
        )
        self.assertEqual((status, error), (400, {"code": "LEASE_REQUEST_INVALID"}))


if __name__ == "__main__":
    unittest.main()
