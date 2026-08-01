#!/usr/bin/env python3
"""Fail-closed nftables egress controller for the shared API/Worker netns."""

from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import hmac
import http.server
import ipaddress
import json
import math
import os
import re
import secrets
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

SCHEMA_VERSION = "1.0"
POLICY_ENGINE_VERSION = "des-nftables-egress-v1"
RESOLVER_POLICY_VERSION = "des-system-dns-v1"
ATTESTATION_HOST = "127.0.0.1"
ATTESTATION_PORT = 17_990
REFRESH_SECONDS = 5.0
STALE_SECONDS = 15.0
MAX_POLICIES = 1_024
MAX_CIDRS_PER_POLICY = 64
MAX_PORTS_PER_POLICY = 32
MAX_RULE_PAIRS = 4_096
MAX_ACTIVE_LEASES = 4_096
MAX_DATABASE_OUTPUT_BYTES = 1024 * 1024
MAX_NFT_OUTPUT_BYTES = 1024 * 1024
MAX_HTTP_BODY_BYTES = 4 * 1024
LOGICAL_LEASE_SECONDS = 30
KERNEL_LEASE_SECONDS = 15
RENEW_AFTER_SECONDS = 5
PASSWORD_PATH = Path("/run/secrets/egress_guard_database_password")
RUNTIME_DIRECTORY = Path("/run/datax-egress-guard")
PGPASS_PATH = RUNTIME_DIRECTORY / "pgpass"
ROUTE_PATH = Path("/proc/net/route")
NFT_BINARY = "/usr/sbin/nft"
# The pinned postgres:15.18-alpine3.24 image installs its client binary in
# /usr/local/bin. Keep an absolute, image-contract path so the guard never
# falls back to a user-controlled PATH lookup.
PSQL_BINARY = "/usr/local/bin/psql"
NFT_TABLE = "des_egress"
HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
NETNS_PATTERN = re.compile(r"^net:\[[0-9]+\]$")
PASSWORD_PATTERN = re.compile(r"^[0-9a-f]{64}$")
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
POLICY_KEYS = {
    "revision_id",
    "policy_hash",
    "resolver_policy_version",
    "egress_policy_version",
    "allowed_cidrs",
    "allowed_ports",
}
POLICY_QUERY = """
WITH bounded AS (
    SELECT *
    FROM des_egress_guard_active_rules_v1
    ORDER BY revision_id
    LIMIT 1025
),
payload AS (
    SELECT COALESCE(
        jsonb_agg(to_jsonb(bounded) ORDER BY revision_id),
        '[]'::jsonb
    ) AS document
    FROM bounded
)
SELECT CASE
    WHEN octet_length(document::text) <= 1048576 THEN document::text
    ELSE NULL
END
FROM payload;
""".strip()


class GuardError(RuntimeError):
    """Expected fail-closed controller error."""


@dataclass(frozen=True, order=True)
class EgressRule:
    network_version: int
    network_address: int
    prefix_length: int
    port: int
    revision_id: str
    policy_hash: str
    cidr: str
    timeout_seconds: int = 0


@dataclass(frozen=True)
class PolicySnapshot:
    policies: dict[str, str]
    rules: tuple[EgressRule, ...]
    policy_set_hash: str


@dataclass(frozen=True)
class EgressLease:
    lease_id: str
    token_hash: bytes
    revision_id: str
    policy_hash: str
    selected_ip: str
    port: int
    expires_monotonic: float
    expires_at: datetime


def utc_now() -> datetime:
    return datetime.now(UTC)


def rfc3339(value: datetime | None) -> str | None:
    if value is None:
        return None
    return (
        value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    )


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


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


def _canonical_uuid(value: object) -> str:
    if not isinstance(value, str):
        raise GuardError("POLICY_REVISION_ID_INVALID")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise GuardError("POLICY_REVISION_ID_INVALID") from exc
    canonical = str(parsed)
    if value != canonical:
        raise GuardError("POLICY_REVISION_ID_NON_CANONICAL")
    return canonical


def _canonical_cidrs(
    value: object,
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_CIDRS_PER_POLICY:
        raise GuardError("POLICY_CIDR_SET_INVALID")
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            raise GuardError("POLICY_CIDR_INVALID")
        try:
            network = ipaddress.ip_network(item, strict=True)
        except ValueError as exc:
            raise GuardError("POLICY_CIDR_INVALID") from exc
        canonical = network.with_prefixlen
        if item != canonical or canonical in seen:
            raise GuardError("POLICY_CIDR_NON_CANONICAL")
        if (
            network.prefixlen == 0
            or network.is_loopback
            or network.is_link_local
            or network.is_multicast
            or network.is_unspecified
        ):
            raise GuardError("POLICY_CIDR_UNSAFE")
        seen.add(canonical)
        networks.append(network)
    ordered = tuple(
        sorted(
            networks,
            key=lambda item: (item.version, int(item.network_address), item.prefixlen),
        )
    )
    if tuple(item.with_prefixlen for item in networks) != tuple(
        item.with_prefixlen for item in ordered
    ):
        raise GuardError("POLICY_CIDR_SET_UNSORTED")
    return ordered


def _canonical_ports(value: object) -> tuple[int, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_PORTS_PER_POLICY:
        raise GuardError("POLICY_PORT_SET_INVALID")
    if any(type(item) is not int or not 1 <= item <= 65_535 for item in value):
        raise GuardError("POLICY_PORT_INVALID")
    ports = tuple(value)
    if ports != tuple(sorted(set(ports))):
        raise GuardError("POLICY_PORT_SET_NON_CANONICAL")
    return ports


def normalize_policy_rows(rows: object) -> PolicySnapshot:
    if not isinstance(rows, list) or len(rows) > MAX_POLICIES:
        raise GuardError("POLICY_SET_INVALID")
    policies: dict[str, str] = {}
    rules: list[EgressRule] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != POLICY_KEYS:
            raise GuardError("POLICY_ROW_INVALID")
        revision_id = _canonical_uuid(row["revision_id"])
        policy_hash = row["policy_hash"]
        if (
            not isinstance(policy_hash, str)
            or HASH_PATTERN.fullmatch(policy_hash) is None
        ):
            raise GuardError("POLICY_HASH_INVALID")
        if row["resolver_policy_version"] != RESOLVER_POLICY_VERSION:
            raise GuardError("RESOLVER_POLICY_VERSION_MISMATCH")
        if row["egress_policy_version"] != POLICY_ENGINE_VERSION:
            raise GuardError("EGRESS_POLICY_VERSION_MISMATCH")
        if revision_id in policies:
            raise GuardError("POLICY_REVISION_DUPLICATE")
        cidrs = _canonical_cidrs(row["allowed_cidrs"])
        ports = _canonical_ports(row["allowed_ports"])
        policies[revision_id] = policy_hash
        for network in cidrs:
            for port in ports:
                rules.append(
                    EgressRule(
                        network_version=network.version,
                        network_address=int(network.network_address),
                        prefix_length=network.prefixlen,
                        port=port,
                        revision_id=revision_id,
                        policy_hash=policy_hash,
                        cidr=network.with_prefixlen,
                    )
                )
                if len(rules) > MAX_RULE_PAIRS:
                    raise GuardError("POLICY_RULE_LIMIT_EXCEEDED")
    ordered_policies = dict(sorted(policies.items()))
    ordered_rules = tuple(sorted(rules))
    policy_set_hash = compute_policy_set_hash(ordered_policies)
    return PolicySnapshot(
        policies=ordered_policies,
        rules=ordered_rules,
        policy_set_hash=policy_set_hash,
    )


def normalize_lease_request(document: object) -> tuple[str, str, str, int]:
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "revision_id",
        "policy_hash",
        "selected_ip",
        "port",
    }:
        raise GuardError("LEASE_REQUEST_INVALID")
    if document["schema_version"] != SCHEMA_VERSION:
        raise GuardError("LEASE_REQUEST_INVALID")
    try:
        revision_id = _canonical_uuid(document["revision_id"])
    except GuardError as exc:
        raise GuardError("LEASE_REQUEST_INVALID") from exc
    policy_hash = document["policy_hash"]
    if not isinstance(policy_hash, str) or HASH_PATTERN.fullmatch(policy_hash) is None:
        raise GuardError("LEASE_REQUEST_INVALID")
    selected_ip = document["selected_ip"]
    if not isinstance(selected_ip, str):
        raise GuardError("LEASE_REQUEST_INVALID")
    try:
        address = ipaddress.ip_address(selected_ip)
    except ValueError as exc:
        raise GuardError("LEASE_REQUEST_INVALID") from exc
    if (
        address.compressed != selected_ip
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or (
            isinstance(address, ipaddress.IPv6Address)
            and address.ipv4_mapped is not None
        )
    ):
        raise GuardError("LEASE_REQUEST_INVALID")
    port = document["port"]
    if type(port) is not int or not 1 <= port <= 65_535:
        raise GuardError("LEASE_REQUEST_INVALID")
    return revision_id, policy_hash, address.compressed, port


def lease_is_allowed(
    snapshot: PolicySnapshot,
    *,
    revision_id: str,
    policy_hash: str,
    selected_ip: str,
    port: int,
) -> bool:
    if snapshot.policies.get(revision_id) != policy_hash:
        return False
    address = ipaddress.ip_address(selected_ip)
    return any(
        rule.revision_id == revision_id
        and rule.policy_hash == policy_hash
        and rule.port == port
        and address in ipaddress.ip_network(rule.cidr)
        for rule in snapshot.rules
    )


def _ipv4_from_proc_hex(value: str) -> ipaddress.IPv4Address:
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise GuardError("CONTROL_ROUTE_INVALID") from exc
    if len(raw) != 4:
        raise GuardError("CONTROL_ROUTE_INVALID")
    return ipaddress.IPv4Address(raw[::-1])


def interface_ipv4_address(interface: str) -> ipaddress.IPv4Address:
    if not interface or len(interface.encode("ascii", "strict")) > 15:
        raise GuardError("CONTROL_INTERFACE_INVALID")
    request = struct.pack("256s", interface.encode("ascii"))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            response = fcntl.ioctl(probe.fileno(), 0x8915, request)
        except OSError as exc:
            raise GuardError("CONTROL_INTERFACE_ADDRESS_UNAVAILABLE") from exc
    return ipaddress.IPv4Address(response[20:24])


def parse_control_route(
    text: str,
    *,
    interface_addresses: dict[str, ipaddress.IPv4Address],
) -> ipaddress.IPv4Network:
    lines = [line.split() for line in text.splitlines() if line.strip()]
    if len(lines) < 3 or lines[0][:8] != [
        "Iface",
        "Destination",
        "Gateway",
        "Flags",
        "RefCnt",
        "Use",
        "Metric",
        "Mask",
    ]:
        raise GuardError("CONTROL_ROUTE_INVALID")
    routes: list[tuple[str, ipaddress.IPv4Network, int, int]] = []
    defaults: list[tuple[int, str]] = []
    for fields in lines[1:]:
        if len(fields) < 8:
            raise GuardError("CONTROL_ROUTE_INVALID")
        interface = fields[0]
        try:
            flags = int(fields[3], 16)
            metric = int(fields[6], 10)
        except ValueError as exc:
            raise GuardError("CONTROL_ROUTE_INVALID") from exc
        destination = _ipv4_from_proc_hex(fields[1])
        mask = _ipv4_from_proc_hex(fields[7])
        if flags & 0x1 == 0:
            continue
        prefix_length = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
        network = ipaddress.IPv4Network((int(destination), prefix_length), strict=False)
        if network.prefixlen == 0:
            defaults.append((metric, interface))
        else:
            routes.append((interface, network, flags, metric))
    if not defaults:
        raise GuardError("CONTROL_DEFAULT_ROUTE_MISSING")
    defaults.sort()
    default_interface = defaults[0][1]
    address = interface_addresses.get(default_interface)
    if address is None:
        raise GuardError("CONTROL_INTERFACE_ADDRESS_UNAVAILABLE")
    matches = [
        network
        for interface, network, _, _ in routes
        if interface == default_interface and address in network
    ]
    if len(matches) != 1:
        raise GuardError("CONTROL_SUBNET_AMBIGUOUS")
    network = matches[0]
    if network.prefixlen == 0 or network.is_loopback or network.is_link_local:
        raise GuardError("CONTROL_SUBNET_UNSAFE")
    return network


def discover_control_network(route_path: Path = ROUTE_PATH) -> ipaddress.IPv4Network:
    try:
        text = route_path.read_text(encoding="ascii")
    except OSError as exc:
        raise GuardError("CONTROL_ROUTE_UNAVAILABLE") from exc
    defaults: list[tuple[int, str]] = []
    for fields in (line.split() for line in text.splitlines()[1:]):
        if len(fields) < 8:
            raise GuardError("CONTROL_ROUTE_INVALID")
        try:
            flags = int(fields[3], 16)
            metric = int(fields[6], 10)
        except ValueError as exc:
            raise GuardError("CONTROL_ROUTE_INVALID") from exc
        if fields[1] == "00000000" and fields[7] == "00000000" and flags & 0x1:
            defaults.append((metric, fields[0]))
    if not defaults:
        raise GuardError("CONTROL_DEFAULT_ROUTE_MISSING")
    default_interface = min(defaults)[1]
    addresses = {default_interface: interface_ipv4_address(default_interface)}
    return parse_control_route(text, interface_addresses=addresses)


def nft_batch(
    control_network: ipaddress.IPv4Network,
    rules: Iterable[EgressRule],
    *,
    table_exists: bool,
) -> str:
    lines: list[str] = []
    if table_exists:
        lines.append(f"delete table inet {NFT_TABLE}")
    rules = tuple(rules)
    seen_endpoints: set[tuple[str, int]] = set()
    for rule in rules:
        maximum_prefix = 32 if rule.network_version == 4 else 128
        address_type = (
            ipaddress.IPv4Address
            if rule.network_version == 4
            else ipaddress.IPv6Address
        )
        if (
            rule.prefix_length != maximum_prefix
            or rule.cidr
            != f"{address_type(rule.network_address).compressed}/{maximum_prefix}"
            or not 1 <= rule.timeout_seconds <= KERNEL_LEASE_SECONDS
            or (rule.cidr, rule.port) in seen_endpoints
        ):
            raise GuardError("NFT_LEASE_RULE_INVALID")
        seen_endpoints.add((rule.cidr, rule.port))
    ipv4_elements = [
        f"{rule.cidr.rsplit('/', 1)[0]} . {rule.port} timeout {rule.timeout_seconds}s"
        for rule in rules
        if rule.network_version == 4
    ]
    ipv6_elements = [
        f"{rule.cidr.rsplit('/', 1)[0]} . {rule.port} timeout {rule.timeout_seconds}s"
        for rule in rules
        if rule.network_version == 6
    ]
    lines.extend(
        [
            f"add table inet {NFT_TABLE}",
            (
                f"add chain inet {NFT_TABLE} output "
                "{ type filter hook output priority 0; policy drop; }"
            ),
            (
                f"add rule inet {NFT_TABLE} output "
                "ip daddr 127.0.0.11 udp dport 53 accept"
            ),
            (
                f"add rule inet {NFT_TABLE} output "
                "ip daddr 127.0.0.11 tcp dport 53 accept"
            ),
            # The API and guard share a netns.  Allow the whole loopback
            # interface rather than only request destination ports: a
            # loopback server's response has the caller's ephemeral port as
            # its destination and would otherwise be dropped by this OUTPUT
            # chain.  This does not create a LAN/WAN route or relax the
            # selected-IP egress policy.
            (
                f"add rule inet {NFT_TABLE} output "
                'oifname "lo" accept'
            ),
            (
                f"add rule inet {NFT_TABLE} output "
                f"ip daddr {control_network.with_prefixlen} accept"
            ),
        ]
    )
    for set_name, element_type, selector, elements in (
        ("allowed_ipv4", "ipv4_addr", "ip daddr", ipv4_elements),
        ("allowed_ipv6", "ipv6_addr", "ip6 daddr", ipv6_elements),
    ):
        if not elements:
            continue
        lines.append(
            f"add set inet {NFT_TABLE} {set_name} "
            "{ "
            f"type {element_type} . inet_service; "
            "flags timeout; "
            f"timeout {KERNEL_LEASE_SECONDS}s; "
            "gc-interval 1s; "
            f"size {MAX_RULE_PAIRS}; "
            "}"
        )
        lines.append(
            f"add element inet {NFT_TABLE} {set_name} {{ " + ", ".join(elements) + " }"
        )
        lines.append(
            f"add rule inet {NFT_TABLE} output "
            f"ct state new,established {selector} . tcp dport @{set_name} accept"
        )
    return "\n".join(lines) + "\n"


class NftablesManager:
    def __init__(
        self, binary: str = NFT_BINARY, runtime_directory: Path = RUNTIME_DIRECTORY
    ) -> None:
        self.binary = binary
        self.runtime_directory = runtime_directory

    @staticmethod
    def _environment() -> dict[str, str]:
        return {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL": "C",
        }

    def _table_exists(self) -> bool:
        result = subprocess.run(
            [self.binary, "list", "table", "inet", NFT_TABLE],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=self._environment(),
            cwd="/",
            timeout=3,
            check=False,
        )
        if result.returncode not in (0, 1):
            raise GuardError("NFT_TABLE_CHECK_FAILED")
        return result.returncode == 0

    def apply(
        self, control_network: ipaddress.IPv4Network, rules: Iterable[EgressRule]
    ) -> str:
        self.runtime_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.runtime_directory, 0o700)
        batch = nft_batch(
            control_network,
            rules,
            table_exists=self._table_exists(),
        )
        temporary_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="ascii",
                prefix="rules-",
                suffix=".nft",
                dir=self.runtime_directory,
                delete=False,
            ) as stream:
                temporary_path = stream.name
                os.chmod(temporary_path, 0o600)
                stream.write(batch)
                stream.flush()
                os.fsync(stream.fileno())
            for arguments in (
                [self.binary, "--check", "--file", temporary_path],
                [self.binary, "--file", temporary_path],
            ):
                result = subprocess.run(
                    arguments,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=self._environment(),
                    cwd="/",
                    timeout=5,
                    check=False,
                )
                if result.returncode != 0:
                    raise GuardError("NFT_ATOMIC_REPLACE_FAILED")
        except (OSError, subprocess.SubprocessError) as exc:
            raise GuardError("NFT_ATOMIC_REPLACE_FAILED") from exc
        finally:
            if temporary_path is not None:
                try:
                    os.unlink(temporary_path)
                except FileNotFoundError:
                    pass
        return self.ruleset_hash()

    def ruleset_hash(self) -> str:
        try:
            result = subprocess.run(
                [self.binary, "--json", "list", "table", "inet", NFT_TABLE],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=self._environment(),
                cwd="/",
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise GuardError("NFT_RULESET_READBACK_FAILED") from exc
        if result.returncode != 0 or not 0 < len(result.stdout) <= MAX_NFT_OUTPUT_BYTES:
            raise GuardError("NFT_RULESET_READBACK_FAILED")
        try:
            document = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GuardError("NFT_RULESET_READBACK_INVALID") from exc
        return sha256_json(_without_nft_runtime_metadata(document))


def _without_nft_runtime_metadata(value: object) -> object:
    """Normalize nft readback without erasing enforced rule semantics.

    ``handle`` is allocated afresh when the guard atomically replaces its
    table.  It identifies a kernel object but does not change what packets
    the object permits.  Hashing it made an unchanged base-deny policy look
    different after every five-second refresh, so independently sampled
    API/Worker attestations could falsely diverge.  ``expires`` is the
    kernel's live countdown for an existing timeout element and is likewise
    not the configured policy.  Deliberately retain fields such as
    ``timeout``, expressions, addresses, ports, hooks and policies: changing
    any of those must still latch drift.
    """

    if isinstance(value, dict):
        return {
            key: _without_nft_runtime_metadata(item)
            for key, item in value.items()
            if key not in {"expires", "handle"}
        }
    if isinstance(value, list):
        return [_without_nft_runtime_metadata(item) for item in value]
    return value


def install_pgpass(
    password_path: Path = PASSWORD_PATH, pgpass_path: Path = PGPASS_PATH
) -> None:
    try:
        raw = password_path.read_bytes()
    except OSError as exc:
        raise GuardError("DATABASE_PASSWORD_UNAVAILABLE") from exc
    if len(raw) != 64:
        raise GuardError("DATABASE_PASSWORD_INVALID")
    try:
        password = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise GuardError("DATABASE_PASSWORD_INVALID") from exc
    if PASSWORD_PATTERN.fullmatch(password) is None:
        raise GuardError("DATABASE_PASSWORD_INVALID")
    pgpass_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(pgpass_path.parent, 0o700)
    descriptor = os.open(
        pgpass_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
            stream.write(f"postgres:5432:datax_studio:datax_egress_guard:{password}\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            pgpass_path.unlink()
        except FileNotFoundError:
            pass
        raise


class PostgresPolicySource:
    @staticmethod
    def _environment() -> dict[str, str]:
        return {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LC_ALL": "C",
            "PGPASSFILE": str(PGPASS_PATH),
            "PGCONNECT_TIMEOUT": "3",
            "PGOPTIONS": "-c statement_timeout=3000 -c default_transaction_read_only=on",
        }

    def load(self) -> PolicySnapshot:
        try:
            result = subprocess.run(
                [
                    PSQL_BINARY,
                    "--host=postgres",
                    "--port=5432",
                    "--dbname=datax_studio",
                    "--username=datax_egress_guard",
                    "--no-password",
                    "--no-psqlrc",
                    "--quiet",
                    "--tuples-only",
                    "--no-align",
                    "--set=ON_ERROR_STOP=1",
                    "--command",
                    POLICY_QUERY,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=self._environment(),
                cwd="/",
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise GuardError("POLICY_DATABASE_UNAVAILABLE") from exc
        if (
            result.returncode != 0
            or not 0 < len(result.stdout) <= MAX_DATABASE_OUTPUT_BYTES
        ):
            raise GuardError("POLICY_DATABASE_UNAVAILABLE")
        try:
            rows = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GuardError("POLICY_DATABASE_RESPONSE_INVALID") from exc
        return normalize_policy_rows(rows)


class AttestationState:
    def __init__(self, network_namespace_id: str) -> None:
        if NETNS_PATTERN.fullmatch(network_namespace_id) is None:
            raise GuardError("NETWORK_NAMESPACE_ID_INVALID")
        self._lock = threading.Lock()
        self._network_namespace_id = network_namespace_id
        self._status = "BLOCKED"
        self._policy_set_hash: str | None = None
        self._policies: dict[str, str] = {}
        self._ruleset_hash: str | None = None
        self._applied_at: datetime | None = None
        self._checked_at = utc_now()

    def verified(
        self, snapshot: PolicySnapshot, ruleset_hash: str, now: datetime
    ) -> None:
        with self._lock:
            self._status = "VERIFIED"
            self._policy_set_hash = snapshot.policy_set_hash
            self._policies = dict(snapshot.policies)
            self._ruleset_hash = ruleset_hash
            self._applied_at = now
            self._checked_at = now

    def blocked(self, ruleset_hash: str | None, now: datetime) -> None:
        with self._lock:
            self._status = "BLOCKED"
            self._policy_set_hash = None
            self._policies = {}
            self._ruleset_hash = ruleset_hash
            self._applied_at = None
            self._checked_at = now

    def document(self, now: datetime | None = None) -> dict[str, object]:
        observed_at = now or utc_now()
        with self._lock:
            status = self._status
            if (observed_at - self._checked_at).total_seconds() > STALE_SECONDS:
                status = "BLOCKED"
            return {
                "schema_version": SCHEMA_VERSION,
                "status": status,
                "policy_engine_version": POLICY_ENGINE_VERSION,
                "resolver_policy_version": RESOLVER_POLICY_VERSION,
                "network_namespace_id": self._network_namespace_id,
                "policy_set_hash": self._policy_set_hash,
                "policies": dict(self._policies),
                "ruleset_hash": self._ruleset_hash,
                "applied_at": rfc3339(self._applied_at),
                "checked_at": rfc3339(self._checked_at),
            }


class GuardController:
    def __init__(
        self,
        *,
        control_network: ipaddress.IPv4Network,
        nftables: NftablesManager,
        policies: PostgresPolicySource,
        state: AttestationState,
    ) -> None:
        self.control_network = control_network
        self.nftables = nftables
        self.policies = policies
        self.state = state
        self._lock = threading.RLock()
        self._expected_ruleset_hash: str | None = None
        self._drift_latched = False
        self._snapshot: PolicySnapshot | None = None
        self._leases: dict[str, EgressLease] = {}

    def install_base_deny(self) -> None:
        with self._lock:
            self._install_base_deny_locked()

    def _install_base_deny_locked(self) -> None:
        now = utc_now()
        self._leases = {}
        self._snapshot = None
        try:
            ruleset_hash = self.nftables.apply(self.control_network, ())
        except GuardError:
            ruleset_hash = None
        self._expected_ruleset_hash = ruleset_hash
        self.state.blocked(ruleset_hash, now)
        if ruleset_hash is None:
            raise GuardError("BASE_DENY_INSTALL_FAILED")

    def _assert_ruleset_unchanged_locked(self) -> None:
        if (
            self._expected_ruleset_hash is not None
            and self.nftables.ruleset_hash() != self._expected_ruleset_hash
        ):
            self._drift_latched = True
            raise GuardError("NFT_RULESET_DRIFT")

    def _reconciled_leases(
        self,
        snapshot: PolicySnapshot,
        now_monotonic: float,
    ) -> tuple[dict[str, EgressLease], bool]:
        leases: dict[str, EgressLease] = {}
        revoked_policy_seen = False
        for lease_id, lease in self._leases.items():
            if lease.expires_monotonic <= now_monotonic:
                continue
            if not lease_is_allowed(
                snapshot,
                revision_id=lease.revision_id,
                policy_hash=lease.policy_hash,
                selected_ip=lease.selected_ip,
                port=lease.port,
            ):
                revoked_policy_seen = True
                continue
            leases[lease_id] = lease
        return leases, revoked_policy_seen

    @staticmethod
    def _lease_rules(
        leases: dict[str, EgressLease],
        now_monotonic: float,
    ) -> tuple[EgressRule, ...]:
        endpoints: dict[tuple[str, int], EgressLease] = {}
        for lease in leases.values():
            key = (lease.selected_ip, lease.port)
            existing = endpoints.get(key)
            if existing is None or lease.expires_monotonic > existing.expires_monotonic:
                endpoints[key] = lease
        rules: list[EgressRule] = []
        for lease in endpoints.values():
            remaining = math.ceil(lease.expires_monotonic - now_monotonic)
            timeout_seconds = min(KERNEL_LEASE_SECONDS, max(1, remaining))
            address = ipaddress.ip_address(lease.selected_ip)
            prefix_length = 32 if address.version == 4 else 128
            rules.append(
                EgressRule(
                    network_version=address.version,
                    network_address=int(address),
                    prefix_length=prefix_length,
                    port=lease.port,
                    revision_id=lease.revision_id,
                    policy_hash=lease.policy_hash,
                    cidr=f"{address.compressed}/{prefix_length}",
                    timeout_seconds=timeout_seconds,
                )
            )
        return tuple(sorted(rules))

    def _apply_locked(
        self,
        snapshot: PolicySnapshot,
        leases: dict[str, EgressLease],
        now_monotonic: float,
    ) -> str:
        rules = self._lease_rules(leases, now_monotonic)
        ruleset_hash = self.nftables.apply(self.control_network, rules)
        self._expected_ruleset_hash = ruleset_hash
        self._snapshot = snapshot
        self._leases = leases
        self.state.verified(snapshot, ruleset_hash, utc_now())
        return ruleset_hash

    def _fail_closed_locked(self, error: GuardError) -> None:
        try:
            self._install_base_deny_locked()
        except GuardError:
            self.state.blocked(None, utc_now())
        raise error

    def refresh_once(self) -> None:
        with self._lock:
            try:
                if self._drift_latched:
                    self._install_base_deny_locked()
                    return
                self._assert_ruleset_unchanged_locked()
                snapshot = self.policies.load()
                now_monotonic = time.monotonic()
                leases, revoked_policy_seen = self._reconciled_leases(
                    snapshot,
                    now_monotonic,
                )
                if revoked_policy_seen:
                    self._install_base_deny_locked()
                    return
                self._apply_locked(snapshot, leases, now_monotonic)
            except GuardError as error:
                try:
                    self._install_base_deny_locked()
                except GuardError:
                    self.state.blocked(None, utc_now())
                if str(error) == "NFT_RULESET_DRIFT":
                    self._drift_latched = True

    def create_lease(self, document: object) -> dict[str, object]:
        revision_id, policy_hash, selected_ip, port = normalize_lease_request(document)
        with self._lock:
            try:
                if self._drift_latched:
                    raise GuardError("LEASE_GUARD_BLOCKED")
                self._assert_ruleset_unchanged_locked()
                snapshot = self.policies.load()
                now_monotonic = time.monotonic()
                leases, revoked_policy_seen = self._reconciled_leases(
                    snapshot,
                    now_monotonic,
                )
                if revoked_policy_seen:
                    raise GuardError("LEASE_POLICY_SET_CHANGED")
                selected_address = ipaddress.ip_address(selected_ip)
                selected_ip_is_control_endpoint = (
                    selected_address.version == self.control_network.version
                    and selected_address in self.control_network
                )
                if selected_ip_is_control_endpoint or not lease_is_allowed(
                    snapshot,
                    revision_id=revision_id,
                    policy_hash=policy_hash,
                    selected_ip=selected_ip,
                    port=port,
                ):
                    self._apply_locked(snapshot, leases, now_monotonic)
                    raise GuardError("LEASE_POLICY_NOT_ACTIVE")
                if len(leases) >= MAX_ACTIVE_LEASES:
                    self._apply_locked(snapshot, leases, now_monotonic)
                    raise GuardError("LEASE_LIMIT_REACHED")
                lease_id = self._new_lease_id(leases)
                token_bytes = bytearray(secrets.token_bytes(32))
                try:
                    bearer_token = (
                        base64.urlsafe_b64encode(token_bytes)
                        .rstrip(b"=")
                        .decode("ascii")
                    )
                    token_hash = self._token_hash(bytes(token_bytes))
                finally:
                    token_bytes[:] = b"\x00" * len(token_bytes)
                now = utc_now()
                lease = EgressLease(
                    lease_id=lease_id,
                    token_hash=token_hash,
                    revision_id=revision_id,
                    policy_hash=policy_hash,
                    selected_ip=selected_ip,
                    port=port,
                    expires_monotonic=now_monotonic + LOGICAL_LEASE_SECONDS,
                    expires_at=now + timedelta(seconds=LOGICAL_LEASE_SECONDS),
                )
                leases[lease_id] = lease
                ruleset_hash = self._apply_locked(snapshot, leases, now_monotonic)
                return self._lease_document(
                    "GRANTED",
                    lease,
                    ruleset_hash,
                    bearer_token=bearer_token,
                )
            except GuardError as error:
                if str(error) in {
                    "LEASE_POLICY_NOT_ACTIVE",
                    "LEASE_LIMIT_REACHED",
                }:
                    raise
                self._fail_closed_locked(error)

    def renew_lease(self, lease_id: str, bearer_token: str) -> dict[str, object]:
        canonical_lease_id = _canonical_uuid(lease_id)
        token_hash = self._validated_token_hash(bearer_token)
        with self._lock:
            existing = self._leases.get(canonical_lease_id)
            if existing is None:
                raise GuardError("LEASE_NOT_FOUND")
            if not hmac.compare_digest(existing.token_hash, token_hash):
                raise GuardError("LEASE_AUTH_INVALID")
            try:
                if self._drift_latched:
                    raise GuardError("LEASE_GUARD_BLOCKED")
                self._assert_ruleset_unchanged_locked()
                snapshot = self.policies.load()
                now_monotonic = time.monotonic()
                leases, revoked_policy_seen = self._reconciled_leases(
                    snapshot,
                    now_monotonic,
                )
                if revoked_policy_seen:
                    raise GuardError("LEASE_POLICY_SET_CHANGED")
                lease = leases.get(canonical_lease_id)
                if lease is None:
                    self._apply_locked(snapshot, leases, now_monotonic)
                    raise GuardError("LEASE_POLICY_NOT_ACTIVE")
                now = utc_now()
                renewed = EgressLease(
                    lease_id=lease.lease_id,
                    token_hash=lease.token_hash,
                    revision_id=lease.revision_id,
                    policy_hash=lease.policy_hash,
                    selected_ip=lease.selected_ip,
                    port=lease.port,
                    expires_monotonic=now_monotonic + LOGICAL_LEASE_SECONDS,
                    expires_at=now + timedelta(seconds=LOGICAL_LEASE_SECONDS),
                )
                leases[canonical_lease_id] = renewed
                ruleset_hash = self._apply_locked(snapshot, leases, now_monotonic)
                return self._lease_document("RENEWED", renewed, ruleset_hash)
            except GuardError as error:
                if str(error) == "LEASE_POLICY_NOT_ACTIVE":
                    raise
                self._fail_closed_locked(error)

    def release_lease(self, lease_id: str, bearer_token: str) -> None:
        canonical_lease_id = _canonical_uuid(lease_id)
        token_hash = self._validated_token_hash(bearer_token)
        with self._lock:
            existing = self._leases.get(canonical_lease_id)
            if existing is None:
                raise GuardError("LEASE_NOT_FOUND")
            if not hmac.compare_digest(existing.token_hash, token_hash):
                raise GuardError("LEASE_AUTH_INVALID")
            try:
                if self._drift_latched:
                    raise GuardError("LEASE_GUARD_BLOCKED")
                self._assert_ruleset_unchanged_locked()
                snapshot = self.policies.load()
                now_monotonic = time.monotonic()
                leases, revoked_policy_seen = self._reconciled_leases(
                    snapshot,
                    now_monotonic,
                )
                if revoked_policy_seen:
                    raise GuardError("LEASE_POLICY_SET_CHANGED")
                leases.pop(canonical_lease_id, None)
                self._apply_locked(snapshot, leases, now_monotonic)
            except GuardError as error:
                self._fail_closed_locked(error)

    @staticmethod
    def _new_lease_id(leases: dict[str, EgressLease]) -> str:
        for _ in range(4):
            candidate = str(uuid4())
            if candidate not in leases:
                return candidate
        raise GuardError("LEASE_ID_GENERATION_FAILED")

    @staticmethod
    def _token_hash(token: bytes) -> bytes:
        return hashlib.sha256(b"DXEGRESSLEASETOKENv1\n" + token).digest()

    @classmethod
    def _validated_token_hash(cls, bearer_token: str) -> bytes:
        if TOKEN_PATTERN.fullmatch(bearer_token) is None:
            raise GuardError("LEASE_AUTH_INVALID")
        try:
            token = base64.urlsafe_b64decode(bearer_token + "=")
        except (ValueError, binascii.Error) as exc:
            raise GuardError("LEASE_AUTH_INVALID") from exc
        if (
            len(token) != 32
            or base64.urlsafe_b64encode(token).rstrip(b"=").decode("ascii")
            != bearer_token
        ):
            raise GuardError("LEASE_AUTH_INVALID")
        return cls._token_hash(token)

    @staticmethod
    def _lease_document(
        status: str,
        lease: EgressLease,
        ruleset_hash: str,
        *,
        bearer_token: str | None = None,
    ) -> dict[str, object]:
        document: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "status": status,
            "lease_id": lease.lease_id,
            "revision_id": lease.revision_id,
            "policy_hash": lease.policy_hash,
            "selected_ip": lease.selected_ip,
            "port": lease.port,
            "expires_at": rfc3339(lease.expires_at),
            "renew_after_seconds": RENEW_AFTER_SECONDS,
            "kernel_timeout_seconds": KERNEL_LEASE_SECONDS,
            "ruleset_hash": ruleset_hash,
        }
        if bearer_token is not None:
            document["bearer_token"] = bearer_token
        return document


class AttestationHandler(http.server.BaseHTTPRequestHandler):
    server_version = "DataXEgressGuard/1"
    sys_version = ""

    def do_GET(self) -> None:
        if self.path != "/v1/attestation":
            self._send_json(404, {"code": "NOT_FOUND"})
            return
        state = self.server.attestation_state
        self._send_json(200, state.document())

    def do_HEAD(self) -> None:
        self._send_json(405, {"code": "METHOD_NOT_ALLOWED"})

    def do_POST(self) -> None:
        if self.path != "/v1/leases":
            self._send_json(404, {"code": "NOT_FOUND"})
            return
        try:
            document = self._read_json_body()
            controller = self.server.guard_controller
            response = controller.create_lease(document)
        except GuardError as error:
            self._send_guard_error(error)
            return
        except Exception:  # noqa: BLE001 - HTTP trust boundary must fail closed.
            self._unexpected_fail_closed()
            return
        self._send_json(201, response)

    def do_PUT(self) -> None:
        try:
            lease_id = self._lease_id_from_path()
            bearer_token = self._bearer_token()
            self._require_empty_body()
            controller = self.server.guard_controller
            response = controller.renew_lease(lease_id, bearer_token)
        except GuardError as error:
            self._send_guard_error(error)
            return
        except Exception:  # noqa: BLE001 - HTTP trust boundary must fail closed.
            self._unexpected_fail_closed()
            return
        self._send_json(200, response)

    def do_DELETE(self) -> None:
        try:
            lease_id = self._lease_id_from_path()
            bearer_token = self._bearer_token()
            self._require_empty_body()
            controller = self.server.guard_controller
            controller.release_lease(lease_id, bearer_token)
        except GuardError as error:
            self._send_guard_error(error)
            return
        except Exception:  # noqa: BLE001 - HTTP trust boundary must fail closed.
            self._unexpected_fail_closed()
            return
        self.send_response(204)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _read_json_body(self) -> object:
        if self.headers.get("Transfer-Encoding") is not None:
            raise GuardError("LEASE_REQUEST_INVALID")
        content_lengths = self.headers.get_all("Content-Length", failobj=[])
        if (
            len(content_lengths) != 1
            or re.fullmatch(r"[1-9][0-9]{0,3}", content_lengths[0]) is None
        ):
            raise GuardError("LEASE_REQUEST_INVALID")
        length = int(content_lengths[0])
        if (
            length > MAX_HTTP_BODY_BYTES
            or self.headers.get("Content-Type") != "application/json"
        ):
            raise GuardError("LEASE_REQUEST_INVALID")
        body = self.rfile.read(length)
        if len(body) != length:
            raise GuardError("LEASE_REQUEST_INVALID")
        try:
            return json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GuardError("LEASE_REQUEST_INVALID") from exc

    def _require_empty_body(self) -> None:
        if self.headers.get("Transfer-Encoding") is not None:
            raise GuardError("LEASE_REQUEST_INVALID")
        content_lengths = self.headers.get_all("Content-Length", failobj=[])
        if len(content_lengths) > 1 or (content_lengths and content_lengths[0] != "0"):
            raise GuardError("LEASE_REQUEST_INVALID")

    def _lease_id_from_path(self) -> str:
        prefix = "/v1/leases/"
        if not self.path.startswith(prefix):
            raise GuardError("LEASE_NOT_FOUND")
        candidate = self.path[len(prefix) :]
        if "/" in candidate or "?" in candidate or "#" in candidate:
            raise GuardError("LEASE_NOT_FOUND")
        try:
            return _canonical_uuid(candidate)
        except GuardError as exc:
            raise GuardError("LEASE_NOT_FOUND") from exc

    def _bearer_token(self) -> str:
        values = self.headers.get_all("Authorization", failobj=[])
        if len(values) != 1 or not values[0].startswith("Bearer "):
            raise GuardError("LEASE_AUTH_INVALID")
        token = values[0][len("Bearer ") :]
        if TOKEN_PATTERN.fullmatch(token) is None:
            raise GuardError("LEASE_AUTH_INVALID")
        return token

    def _unexpected_fail_closed(self) -> None:
        controller = self.server.guard_controller
        try:
            controller.install_base_deny()
        except GuardError:
            pass
        self._send_json(503, {"code": "LEASE_GUARD_BLOCKED"})

    def _send_guard_error(self, error: GuardError) -> None:
        code = str(error)
        if code in {"LEASE_REQUEST_INVALID"}:
            status = 400
        elif code == "LEASE_AUTH_INVALID":
            status = 401
        elif code == "LEASE_NOT_FOUND":
            status = 404
        elif code == "LEASE_POLICY_NOT_ACTIVE":
            status = 409
        elif code == "LEASE_LIMIT_REACHED":
            status = 429
        else:
            status = 503
        self._send_json(status, {"code": code})

    def _send_json(self, status: int, document: object) -> None:
        body = canonical_json(document) + b"\n"
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def log_message(self, _format: str, *_arguments: object) -> None:
        return


class AttestationServer(http.server.ThreadingHTTPServer):
    # A process restart may otherwise fail closed for an avoidable TIME_WAIT
    # interval even though no other listener owns the loopback control port.
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 16

    def __init__(
        self,
        address: tuple[str, int],
        state: AttestationState,
        controller: GuardController,
    ) -> None:
        self.attestation_state = state
        self.guard_controller = controller
        super().__init__(address, AttestationHandler)

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        connection, address = super().get_request()
        connection.settimeout(2.0)
        return connection, address


def network_namespace_id() -> str:
    try:
        value = os.readlink("/proc/self/ns/net")
    except OSError as exc:
        raise GuardError("NETWORK_NAMESPACE_ID_UNAVAILABLE") from exc
    if NETNS_PATTERN.fullmatch(value) is None:
        raise GuardError("NETWORK_NAMESPACE_ID_INVALID")
    return value


def run() -> None:
    RUNTIME_DIRECTORY.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(RUNTIME_DIRECTORY, 0o700)
    try:
        PGPASS_PATH.unlink()
    except FileNotFoundError:
        pass
    install_pgpass()
    control_network = discover_control_network()
    state = AttestationState(network_namespace_id())
    controller = GuardController(
        control_network=control_network,
        nftables=NftablesManager(),
        policies=PostgresPolicySource(),
        state=state,
    )
    controller.install_base_deny()

    stopped = threading.Event()

    def stop(_signum: int, _frame: object) -> None:
        stopped.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    def refresh_loop() -> None:
        while not stopped.is_set():
            try:
                controller.refresh_once()
            except Exception:  # noqa: BLE001 - controller loop must fail closed.
                try:
                    controller.install_base_deny()
                except GuardError:
                    state.blocked(None, utc_now())
            stopped.wait(REFRESH_SECONDS)

    refresher = threading.Thread(
        target=refresh_loop,
        name="egress-policy-refresh",
        daemon=True,
    )
    refresher.start()
    server = AttestationServer(
        (ATTESTATION_HOST, ATTESTATION_PORT),
        state,
        controller,
    )
    server.timeout = 1.0
    try:
        while not stopped.is_set():
            server.handle_request()
    finally:
        server.server_close()
        stopped.set()
        refresher.join(timeout=REFRESH_SECONDS + 1)
        try:
            controller.install_base_deny()
        except GuardError:
            pass
        try:
            PGPASS_PATH.unlink()
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    try:
        run()
    except GuardError:
        raise SystemExit(1)
