from __future__ import annotations

import base64
import copy
import hashlib
import json
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator, FormatChecker

from datax_studio.release_qualification import (
    ExpectedHarness,
    QualificationNonceUse,
    QualificationVerificationError,
    parse_release_payload,
    payload_binding,
    verify_harness_qualification,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PAYLOAD_SCHEMA = REPOSITORY_ROOT / "docs/contracts/release-payload.v1.schema.json"
QUALIFICATION_SCHEMA = REPOSITORY_ROOT / "docs/contracts/harness-qualification.v1.schema.json"
NOW = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)
PAYLOAD_DOMAIN = b"DES-RELEASE-PAYLOAD-v1\n"
QUALIFICATION_DOMAIN = b"DES-HARNESS-QUALIFICATION-v1\n"
IMAGE_ROLES = ("api", "egress_guard", "postgres", "web", "worker")
PLUGIN_NAMES = ("mysqlreader", "mysqlwriter", "postgresqlreader", "postgresqlwriter")


class _NonceLedger:
    def __init__(self) -> None:
        self.calls: list[QualificationNonceUse] = []
        self._used: set[tuple[str, str]] = set()

    def consume(self, nonce_use: QualificationNonceUse) -> bool:
        self.calls.append(nonce_use)
        key = (nonce_use.issuer_key_id, nonce_use.nonce)
        if key in self._used:
            return False
        self._used.add(key)
        return True


class _AlwaysEqualHarness(ExpectedHarness):
    def __eq__(self, _other: object) -> bool:
        return True


class _AlwaysEqualString(str):
    def __eq__(self, _other: object) -> bool:
        return True

    def __ne__(self, _other: object) -> bool:
        return False


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _artifact(name: str) -> dict[str, str]:
    return {"path": f"evidence/{name}.json", "sha256": _hash(name)}


def _canonical(document: dict[str, object]) -> bytes:
    return rfc8785.dumps(document)


def _payload(private_key: Ed25519PrivateKey) -> dict[str, object]:
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    commit = "a" * 40
    document: dict[str, object] = {
        "schema_version": "1.0",
        "artifact_kind": "RELEASE_PAYLOAD",
        "identity": {
            "repository": "xiaoli2hust/datax",
            "source_ref": "refs/heads/main",
            "commit_sha": commit,
            "product_version": "0.1.0",
            "release_candidate": f"0.1.0-{commit[:12]}",
        },
        "target_platforms": {"windows_host": "windows-x64", "linux_runtime": "linux-amd64"},
        "images": [
            {
                "role": role,
                "reference": f"ghcr.io/xiaoli2hust/datax-{role}@sha256:{_hash(role)}",
            }
            for role in IMAGE_ROLES
        ],
        "worker_runtime": {
            "datax_release": "datax_v202309",
            "jdk_version": "OpenJDK 8u472",
            "runtime_manifest": _artifact("runtime-manifest"),
            "runtime_tree_sha256": _hash("runtime-tree"),
            "plugins": [
                {
                    "name": name,
                    "jar": _artifact(f"{name}-jar"),
                    "upstream": {
                        "repository": "https://github.com/alibaba/DataX.git",
                        "commit_sha": "b" * 40,
                        "module_path": f"{name}/src/main",
                    },
                    "parameter_boundary_contract_version": "1.0",
                    "dependency_inventory": _artifact(f"{name}-dependencies"),
                    "license_review": _artifact(f"{name}-license"),
                }
                for name in PLUGIN_NAMES
            ],
        },
        "hqa_keyring": {
            "keyring_id": "hqa-keyring-0001",
            "keys": [
                {
                    "key_id": "hqa-key-0001",
                    "algorithm": "Ed25519",
                    "public_key_base64": base64.b64encode(public_key).decode("ascii"),
                    "not_before": "2026-08-01T00:00:00Z",
                    "valid_until": "2026-09-01T00:00:00Z",
                }
            ],
        },
        "artifacts": {
            "build_identity": _artifact("build-identity"),
            "image_lock": _artifact("images-lock"),
            "source_sbom": _artifact("source-sbom"),
            "image_sboms": [
                {"role": role, "artifact": _artifact(f"{role}-sbom")}
                for role in IMAGE_ROLES
            ],
            "license_inventory": _artifact("license-inventory"),
        },
    }
    document["payload_root_sha256"] = hashlib.sha256(
        PAYLOAD_DOMAIN + _canonical(document)
    ).hexdigest()
    return document


def _binding(payload: dict[str, object]) -> dict[str, object]:
    return {
        "payload_root_sha256": payload["payload_root_sha256"],
        "identity": copy.deepcopy(payload["identity"]),
        "target_platforms": copy.deepcopy(payload["target_platforms"]),
        "images": copy.deepcopy(payload["images"]),
        "worker_runtime": copy.deepcopy(payload["worker_runtime"]),
        "artifacts": copy.deepcopy(payload["artifacts"]),
    }


def _refresh_payload_root(payload: dict[str, object]) -> None:
    unsigned = dict(payload)
    unsigned.pop("payload_root_sha256", None)
    payload["payload_root_sha256"] = hashlib.sha256(
        PAYLOAD_DOMAIN + _canonical(unsigned)
    ).hexdigest()


def _schema_accepts(schema_path: Path, document: object) -> bool:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker()).is_valid(document)


def _expected_harness() -> ExpectedHarness:
    return ExpectedHarness(
        identity="phase-a-win-harness",
        environment_id="win11-qualification-01",
        environment_manifest_sha256=_hash("windows-environment"),
        harness_version="1.0.0",
    )


def _qualification_unsigned(payload: dict[str, object]) -> dict[str, object]:
    expected = _expected_harness()
    return {
        "schema_version": "1.0",
        "artifact_kind": "HARNESS_QUALIFICATION",
        "qualification_id": "qh-qualification-0001",
        "purpose": "QUALIFICATION_HARNESS",
        "issuer_key_id": "hqa-key-0001",
        "issued_at": "2026-08-02T11:00:00Z",
        "not_before": "2026-08-02T11:00:00Z",
        "valid_until": "2026-08-02T13:00:00Z",
        "nonce": "n" * 32,
        "payload_binding": _binding(payload),
        "harness": {
            "identity": expected.identity,
            "environment_id": expected.environment_id,
            "environment_manifest_sha256": expected.environment_manifest_sha256,
            "harness_version": expected.harness_version,
        },
    }


def _signed_qualification(
    unsigned: dict[str, object],
    private_key: Ed25519PrivateKey,
    *,
    domain: bytes = QUALIFICATION_DOMAIN,
) -> dict[str, object]:
    signature = private_key.sign(domain + _canonical(unsigned))
    return {
        **unsigned,
        "signature": {
            "algorithm": "Ed25519",
            "value_base64": base64.b64encode(signature).decode("ascii"),
        },
    }


def _parsed_payload(payload: dict[str, object]):
    return parse_release_payload(
        _canonical(payload),
        expected_payload_root_sha256=str(payload["payload_root_sha256"]),
    )


def _assert_code(callback: Callable[[], object], expected: str) -> None:
    try:
        callback()
    except QualificationVerificationError as error:
        assert error.code == expected
    else:
        raise AssertionError(f"expected {expected}")


def test_canonical_payload_and_qh_verify_against_only_payload_keyring() -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload(private_key)
    qualification = _signed_qualification(_qualification_unsigned(payload), private_key)
    payload_schema = json.loads(PAYLOAD_SCHEMA.read_text(encoding="utf-8"))
    qualification_schema = json.loads(QUALIFICATION_SCHEMA.read_text(encoding="utf-8"))

    Draft202012Validator(payload_schema, format_checker=FormatChecker()).validate(payload)
    Draft202012Validator(
        qualification_schema,
        format_checker=FormatChecker(),
    ).validate(qualification)

    ledger = _NonceLedger()
    verified = verify_harness_qualification(
        _canonical(qualification),
        release_payload=_parsed_payload(payload),
        expected_harness=_expected_harness(),
        now=NOW,
        consume_nonce=ledger.consume,
    )

    assert verified.qualification_id == "qh-qualification-0001"
    assert verified.payload_root_sha256 == payload["payload_root_sha256"]
    assert verified.issuer_key_id == "hqa-key-0001"
    assert len(ledger.calls) == 1


def test_qh_rejects_an_always_equal_expected_harness_subclass() -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload(private_key)
    malicious_harness = _AlwaysEqualHarness(
        identity="forged-phase-a-harness",
        environment_id="win11-qualification-01",
        environment_manifest_sha256=_hash("windows-environment"),
        harness_version="1.0.0",
    )

    _assert_code(
        lambda: verify_harness_qualification(
            _canonical(_signed_qualification(_qualification_unsigned(payload), private_key)),
            release_payload=_parsed_payload(payload),
            expected_harness=malicious_harness,
            now=NOW,
            consume_nonce=_NonceLedger().consume,
        ),
        "QH_EXPECTED_HARNESS_INVALID",
    )


def test_qh_rejects_an_always_equal_harness_string_subclass() -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload(private_key)
    malicious_harness = ExpectedHarness(
        identity=_AlwaysEqualString("forged-phase-a-harness"),
        environment_id="win11-qualification-01",
        environment_manifest_sha256=_hash("windows-environment"),
        harness_version="1.0.0",
    )

    _assert_code(
        lambda: verify_harness_qualification(
            _canonical(_signed_qualification(_qualification_unsigned(payload), private_key)),
            release_payload=_parsed_payload(payload),
            expected_harness=malicious_harness,
            now=NOW,
            consume_nonce=_NonceLedger().consume,
        ),
        "QH_EXPECTED_HARNESS_INVALID",
    )

def test_verified_payload_exposes_a_canonical_complete_binding_digest() -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload(private_key)

    binding = payload_binding(_parsed_payload(payload))

    assert binding.payload_root_sha256 == payload["payload_root_sha256"]
    assert binding.payload_binding_sha256 == hashlib.sha256(
        _canonical(_binding(payload))
    ).hexdigest()
    assert binding.worker_image_digest == f"sha256:{_hash('worker')}"
    assert binding.plugin_sha256s == tuple(
        (name, _hash(f"{name}-jar")) for name in PLUGIN_NAMES
    )


def test_verified_payload_does_not_retain_replaceable_binding_or_keyring_facts() -> None:
    private_key = Ed25519PrivateKey.generate()
    parsed = _parsed_payload(_payload(private_key))

    _assert_code(
        lambda: payload_binding(
            replace(parsed, _canonical_without_root=b'{"artifact_kind":"RELEASE_PAYLOAD"}')
        ),
        "RELEASE_PAYLOAD_NOT_VERIFIED",
    )
    _assert_code(
        lambda: payload_binding(
            replace(parsed, _canonical_without_root="not-bytes", _integrity_tag="")
        ),
        "RELEASE_PAYLOAD_NOT_VERIFIED",
    )
    with pytest.raises(TypeError):
        replace(parsed, _payload_binding=object())
    with pytest.raises(TypeError):
        replace(parsed, _hqa_keys=())

    assert not hasattr(parsed, "_payload_binding")
    assert not hasattr(parsed, "_binding_canonical")
    assert not hasattr(parsed, "_hqa_keys")


def test_payload_requires_own_root_and_independent_expected_root() -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload(private_key)
    tampered = copy.deepcopy(payload)
    tampered["identity"]["source_ref"] = "refs/tags/v0.1.0"  # type: ignore[index]

    _assert_code(
        lambda: parse_release_payload(
            _canonical(tampered),
            expected_payload_root_sha256=str(payload["payload_root_sha256"]),
        ),
        "RELEASE_PAYLOAD_ROOT_MISMATCH",
    )
    _assert_code(
        lambda: parse_release_payload(
            _canonical(payload),
            expected_payload_root_sha256="0" * 64,
        ),
        "RELEASE_PAYLOAD_EXPECTED_ROOT_MISMATCH",
    )


def test_payload_and_qh_reject_duplicate_bom_noncanonical_and_nonfinite_json() -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload(private_key)
    canonical = _canonical(payload)

    _assert_code(
        lambda: parse_release_payload(
            json.dumps(payload, indent=2).encode("utf-8"),
            expected_payload_root_sha256=str(payload["payload_root_sha256"]),
        ),
        "RELEASE_PAYLOAD_CANONICAL_JSON_REQUIRED",
    )
    _assert_code(
        lambda: parse_release_payload(
            b'{"schema_version":"1.0","schema_version":"1.0"}',
            expected_payload_root_sha256=str(payload["payload_root_sha256"]),
        ),
        "RELEASE_PAYLOAD_DUPLICATE_JSON_KEY",
    )
    _assert_code(
        lambda: parse_release_payload(
            b"\xef\xbb\xbf" + canonical,
            expected_payload_root_sha256=str(payload["payload_root_sha256"]),
        ),
        "RELEASE_PAYLOAD_CANONICAL_JSON_REQUIRED",
    )
    _assert_code(
        lambda: verify_harness_qualification(
            b'{"not_a_qualification":NaN}',
            release_payload=_parsed_payload(payload),
            expected_harness=_expected_harness(),
            now=NOW,
            consume_nonce=_NonceLedger().consume,
        ),
        "HARNESS_QUALIFICATION_JSON_INVALID",
    )
    _assert_code(
        lambda: verify_harness_qualification(
            b'{"not_a_qualification":1e0}',
            release_payload=_parsed_payload(payload),
            expected_harness=_expected_harness(),
            now=NOW,
            consume_nonce=_NonceLedger().consume,
        ),
        "HARNESS_QUALIFICATION_CANONICAL_JSON_REQUIRED",
    )


def test_tamper_wrong_key_and_wrong_domain_do_not_consume_nonce() -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload(private_key)
    unsigned = _qualification_unsigned(payload)
    qualification = _signed_qualification(unsigned, private_key)
    tampered = copy.deepcopy(qualification)
    tampered["qualification_id"] = "qh-tampered-0001"
    ledger = _NonceLedger()

    _assert_code(
        lambda: verify_harness_qualification(
            _canonical(tampered),
            release_payload=_parsed_payload(payload),
            expected_harness=_expected_harness(),
            now=NOW,
            consume_nonce=ledger.consume,
        ),
        "QH_SIGNATURE_INVALID",
    )
    _assert_code(
        lambda: verify_harness_qualification(
            _canonical(_signed_qualification(unsigned, Ed25519PrivateKey.generate())),
            release_payload=_parsed_payload(payload),
            expected_harness=_expected_harness(),
            now=NOW,
            consume_nonce=ledger.consume,
        ),
        "QH_SIGNATURE_INVALID",
    )
    _assert_code(
        lambda: verify_harness_qualification(
            _canonical(_signed_qualification(unsigned, private_key, domain=b"wrong-domain\n")),
            release_payload=_parsed_payload(payload),
            expected_harness=_expected_harness(),
            now=NOW,
            consume_nonce=ledger.consume,
        ),
        "QH_SIGNATURE_INVALID",
    )

    assert ledger.calls == []


def test_qh_compares_its_full_signed_snapshot_to_p_and_rejects_self_key() -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload(private_key)
    unsigned = _qualification_unsigned(payload)
    altered = copy.deepcopy(unsigned)
    altered["payload_binding"]["worker_runtime"]["jdk_version"] = "OpenJDK 8u999"  # type: ignore[index]
    ledger = _NonceLedger()

    _assert_code(
        lambda: verify_harness_qualification(
            _canonical(_signed_qualification(altered, private_key)),
            release_payload=_parsed_payload(payload),
            expected_harness=_expected_harness(),
            now=NOW,
            consume_nonce=ledger.consume,
        ),
        "QH_PAYLOAD_BINDING_MISMATCH",
    )
    wrong_root = copy.deepcopy(unsigned)
    wrong_root["payload_binding"]["payload_root_sha256"] = "0" * 64  # type: ignore[index]
    _assert_code(
        lambda: verify_harness_qualification(
            _canonical(_signed_qualification(wrong_root, private_key)),
            release_payload=_parsed_payload(payload),
            expected_harness=_expected_harness(),
            now=NOW,
            consume_nonce=ledger.consume,
        ),
        "QH_PAYLOAD_BINDING_MISMATCH",
    )
    self_key = copy.deepcopy(unsigned)
    self_key["public_key_base64"] = base64.b64encode(b"x" * 32).decode("ascii")
    _assert_code(
        lambda: verify_harness_qualification(
            _canonical(_signed_qualification(self_key, private_key)),
            release_payload=_parsed_payload(payload),
            expected_harness=_expected_harness(),
            now=NOW,
            consume_nonce=ledger.consume,
        ),
        "QH_FORMAT_INVALID",
    )
    assert ledger.calls == []


def test_qh_time_window_and_nonce_replay_are_fail_closed() -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload(private_key)
    qualification = _signed_qualification(_qualification_unsigned(payload), private_key)
    ledger = _NonceLedger()

    verify_harness_qualification(
        _canonical(qualification),
        release_payload=_parsed_payload(payload),
        expected_harness=_expected_harness(),
        now=NOW,
        consume_nonce=ledger.consume,
    )
    _assert_code(
        lambda: verify_harness_qualification(
            _canonical(qualification),
            release_payload=_parsed_payload(payload),
            expected_harness=_expected_harness(),
            now=NOW,
            consume_nonce=ledger.consume,
        ),
        "QH_NONCE_REPLAYED",
    )
    different_qualification_id = _qualification_unsigned(payload)
    different_qualification_id["qualification_id"] = "qh-qualification-0002"
    _assert_code(
        lambda: verify_harness_qualification(
            _canonical(_signed_qualification(different_qualification_id, private_key)),
            release_payload=_parsed_payload(payload),
            expected_harness=_expected_harness(),
            now=NOW,
            consume_nonce=ledger.consume,
        ),
        "QH_NONCE_REPLAYED",
    )
    expired = _qualification_unsigned(payload)
    expired["issued_at"] = "2026-08-02T08:00:00Z"
    expired["not_before"] = "2026-08-02T08:00:00Z"
    expired["valid_until"] = "2026-08-02T10:00:00Z"
    _assert_code(
        lambda: verify_harness_qualification(
            _canonical(_signed_qualification(expired, private_key)),
            release_payload=_parsed_payload(payload),
            expected_harness=_expected_harness(),
            now=NOW,
            consume_nonce=_NonceLedger().consume,
        ),
        "QH_NOT_CURRENTLY_VALID",
    )
    too_long = _qualification_unsigned(payload)
    too_long["valid_until"] = "2026-08-03T12:00:01Z"
    _assert_code(
        lambda: verify_harness_qualification(
            _canonical(_signed_qualification(too_long, private_key)),
            release_payload=_parsed_payload(payload),
            expected_harness=_expected_harness(),
            now=NOW,
            consume_nonce=_NonceLedger().consume,
        ),
        "QH_VALIDITY_WINDOW_TOO_LONG",
    )
    non_utc = _qualification_unsigned(payload)
    non_utc["issued_at"] = "2026-08-02T11:00:00+00:00"
    _assert_code(
        lambda: verify_harness_qualification(
            _canonical(_signed_qualification(non_utc, private_key)),
            release_payload=_parsed_payload(payload),
            expected_harness=_expected_harness(),
            now=NOW,
            consume_nonce=_NonceLedger().consume,
        ),
        "QH_FORMAT_INVALID",
    )
    excess_fraction = _qualification_unsigned(payload)
    excess_fraction["not_before"] = "2026-08-02T11:00:00.0000001Z"
    _assert_code(
        lambda: verify_harness_qualification(
            _canonical(_signed_qualification(excess_fraction, private_key)),
            release_payload=_parsed_payload(payload),
            expected_harness=_expected_harness(),
            now=NOW,
            consume_nonce=_NonceLedger().consume,
        ),
        "QH_TIMESTAMP_INVALID",
    )


def test_unknown_hqa_key_and_harness_mismatch_are_fail_closed() -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload(private_key)
    unknown = _qualification_unsigned(payload)
    unknown["issuer_key_id"] = "hqa-key-unknown"
    ledger = _NonceLedger()

    _assert_code(
        lambda: verify_harness_qualification(
            _canonical(_signed_qualification(unknown, private_key)),
            release_payload=_parsed_payload(payload),
            expected_harness=_expected_harness(),
            now=NOW,
            consume_nonce=ledger.consume,
        ),
        "QH_ISSUER_KEY_UNKNOWN",
    )
    _assert_code(
        lambda: verify_harness_qualification(
            _canonical(_signed_qualification(_qualification_unsigned(payload), private_key)),
            release_payload=_parsed_payload(payload),
            expected_harness=ExpectedHarness(
                identity="another-win-harness",
                environment_id="win11-qualification-01",
                environment_manifest_sha256=_hash("windows-environment"),
                harness_version="1.0.0",
            ),
            now=NOW,
            consume_nonce=ledger.consume,
        ),
        "QH_HARNESS_IDENTITY_MISMATCH",
    )
    assert ledger.calls == []


def test_release_payload_and_qh_contracts_match_the_strict_parser_boundaries() -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload(private_key)

    unsafe_path = copy.deepcopy(payload)
    unsafe_path["artifacts"]["source_sbom"]["path"] = "evidence/../escape.json"  # type: ignore[index]
    _refresh_payload_root(unsafe_path)
    assert not _schema_accepts(PAYLOAD_SCHEMA, unsafe_path)
    _assert_code(
        lambda: _parsed_payload(unsafe_path),
        "RELEASE_PAYLOAD_FORMAT_INVALID",
    )

    newline_digest = copy.deepcopy(payload)
    newline_digest["payload_root_sha256"] = f"{payload['payload_root_sha256']}\n"
    assert not _schema_accepts(PAYLOAD_SCHEMA, newline_digest)
    _assert_code(
        lambda: parse_release_payload(
            _canonical(newline_digest),
            expected_payload_root_sha256=str(payload["payload_root_sha256"]),
        ),
        "RELEASE_PAYLOAD_FORMAT_INVALID",
    )

    wrong_image_order = copy.deepcopy(payload)
    wrong_image_order["images"][0], wrong_image_order["images"][1] = (  # type: ignore[index]
        wrong_image_order["images"][1],  # type: ignore[index]
        wrong_image_order["images"][0],  # type: ignore[index]
    )
    _refresh_payload_root(wrong_image_order)
    assert not _schema_accepts(PAYLOAD_SCHEMA, wrong_image_order)
    _assert_code(
        lambda: _parsed_payload(wrong_image_order),
        "RELEASE_PAYLOAD_FORMAT_INVALID",
    )

    too_many_keys = copy.deepcopy(payload)
    template_key = too_many_keys["hqa_keyring"]["keys"][0]  # type: ignore[index]
    too_many_keys["hqa_keyring"]["keys"] = [  # type: ignore[index]
        {**template_key, "key_id": f"hqa-key-{index:04}"}  # type: ignore[arg-type]
        for index in range(1, 18)
    ]
    _refresh_payload_root(too_many_keys)
    assert not _schema_accepts(PAYLOAD_SCHEMA, too_many_keys)
    _assert_code(
        lambda: _parsed_payload(too_many_keys),
        "RELEASE_PAYLOAD_FORMAT_INVALID",
    )

    excessive_fraction = copy.deepcopy(payload)
    excessive_fraction["hqa_keyring"]["keys"][0]["valid_until"] = (  # type: ignore[index]
        "2026-09-01T00:00:00.0000001Z"
    )
    _refresh_payload_root(excessive_fraction)
    assert not _schema_accepts(PAYLOAD_SCHEMA, excessive_fraction)
    _assert_code(
        lambda: _parsed_payload(excessive_fraction),
        "RELEASE_PAYLOAD_KEY_TIME_INVALID",
    )

    unsigned = _qualification_unsigned(payload)
    unsigned["payload_binding"]["images"][0], unsigned["payload_binding"]["images"][1] = (  # type: ignore[index]
        unsigned["payload_binding"]["images"][1],  # type: ignore[index]
        unsigned["payload_binding"]["images"][0],  # type: ignore[index]
    )
    invalid_qualification = _signed_qualification(unsigned, private_key)
    assert not _schema_accepts(QUALIFICATION_SCHEMA, invalid_qualification)
    _assert_code(
        lambda: verify_harness_qualification(
            _canonical(invalid_qualification),
            release_payload=_parsed_payload(payload),
            expected_harness=_expected_harness(),
            now=NOW,
            consume_nonce=_NonceLedger().consume,
        ),
        "QH_FORMAT_INVALID",
    )

    fractional_qualification = _qualification_unsigned(payload)
    fractional_qualification["not_before"] = "2026-08-02T11:00:00.0000001Z"
    assert not _schema_accepts(
        QUALIFICATION_SCHEMA,
        _signed_qualification(fractional_qualification, private_key),
    )


def test_deep_json_is_rejected_with_a_stable_error() -> None:
    deeply_nested = b"null"
    for _ in range(1000):
        deeply_nested = b'{"x":' + deeply_nested + b"}"

    _assert_code(
        lambda: parse_release_payload(
            deeply_nested,
            expected_payload_root_sha256="0" * 64,
        ),
        "RELEASE_PAYLOAD_JSON_INVALID",
    )
    private_key = Ed25519PrivateKey.generate()
    payload = _payload(private_key)
    _assert_code(
        lambda: verify_harness_qualification(
            deeply_nested,
            release_payload=_parsed_payload(payload),
            expected_harness=_expected_harness(),
            now=NOW,
            consume_nonce=_NonceLedger().consume,
        ),
        "HARNESS_QUALIFICATION_JSON_INVALID",
    )
