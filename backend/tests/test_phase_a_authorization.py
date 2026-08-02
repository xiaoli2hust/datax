from __future__ import annotations

import base64
import copy
import hashlib
from dataclasses import dataclass, replace
from datetime import UTC, datetime

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from datax_studio.qualification.phase_a import (
    PhaseAAuthorizationError,
    PhaseARuntimeIdentity,
    activate_harness_authorization,
    assert_execution_binding,
    bind_execution,
)
from datax_studio.release_qualification import (
    ExpectedHarness,
    QualificationNonceUse,
    parse_release_payload,
)

NOW = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)
PAYLOAD_DOMAIN = b"DES-RELEASE-PAYLOAD-v1\n"
QUALIFICATION_DOMAIN = b"DES-HARNESS-QUALIFICATION-v1\n"
IMAGE_ROLES = ("api", "egress_guard", "postgres", "web", "worker")
PLUGIN_NAMES = ("mysqlreader", "mysqlwriter", "postgresqlreader", "postgresqlwriter")


@dataclass(frozen=True)
class _Version:
    datax_release: str
    runtime_sha256: str
    reader_plugin_name: str
    reader_plugin_sha256: str
    writer_plugin_name: str
    writer_plugin_sha256: str


class _NonceLedger:
    def __init__(self) -> None:
        self.calls: list[QualificationNonceUse] = []
        self.used: set[tuple[str, str]] = set()

    def consume(self, value: QualificationNonceUse) -> bool:
        self.calls.append(value)
        key = (value.issuer_key_id, value.nonce)
        if key in self.used:
            return False
        self.used.add(key)
        return True


class _AlwaysEqualString(str):
    def __eq__(self, _other: object) -> bool:
        return True

    def __ne__(self, _other: object) -> bool:
        return False


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical(document: dict[str, object]) -> bytes:
    return rfc8785.dumps(document)


def _artifact(name: str) -> dict[str, str]:
    return {"path": f"evidence/{name}.json", "sha256": _hash(name)}


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


def _expected_harness() -> ExpectedHarness:
    return ExpectedHarness(
        identity="phase-a-win-harness",
        environment_id="win11-qualification-01",
        environment_manifest_sha256=_hash("windows-environment"),
        harness_version="1.0.0",
    )


def _qualification(
    payload: dict[str, object],
    private_key: Ed25519PrivateKey,
) -> bytes:
    harness = _expected_harness()
    unsigned: dict[str, object] = {
        "schema_version": "1.0",
        "artifact_kind": "HARNESS_QUALIFICATION",
        "qualification_id": "qh-qualification-0001",
        "purpose": "QUALIFICATION_HARNESS",
        "issuer_key_id": "hqa-key-0001",
        "issued_at": "2026-08-02T11:00:00Z",
        "not_before": "2026-08-02T11:00:00Z",
        "valid_until": "2026-08-02T13:00:00Z",
        "nonce": "n" * 32,
        "payload_binding": {
            "payload_root_sha256": payload["payload_root_sha256"],
            "identity": copy.deepcopy(payload["identity"]),
            "target_platforms": copy.deepcopy(payload["target_platforms"]),
            "images": copy.deepcopy(payload["images"]),
            "worker_runtime": copy.deepcopy(payload["worker_runtime"]),
            "artifacts": copy.deepcopy(payload["artifacts"]),
        },
        "harness": {
            "identity": harness.identity,
            "environment_id": harness.environment_id,
            "environment_manifest_sha256": harness.environment_manifest_sha256,
            "harness_version": harness.harness_version,
        },
    }
    signature = private_key.sign(QUALIFICATION_DOMAIN + _canonical(unsigned))
    return _canonical(
        {
            **unsigned,
            "signature": {
                "algorithm": "Ed25519",
                "value_base64": base64.b64encode(signature).decode("ascii"),
            },
        }
    )


def _runtime() -> PhaseARuntimeIdentity:
    return PhaseARuntimeIdentity(
        worker_image_digest=f"sha256:{_hash('worker')}",
        datax_release="datax_v202309",
        runtime_sha256=_hash("runtime-tree"),
        plugin_sha256s={name: _hash(f"{name}-jar") for name in PLUGIN_NAMES},
    )


def _release_payload(payload: dict[str, object]):
    return parse_release_payload(
        _canonical(payload),
        expected_payload_root_sha256=str(payload["payload_root_sha256"]),
    )


def _assert_code(callback: object, expected: str) -> None:
    try:
        assert callable(callback)
        callback()
    except PhaseAAuthorizationError as error:
        assert error.code == expected
    else:
        raise AssertionError(f"expected {expected}")


def test_private_phase_a_authorization_binds_verified_p_qh_runtime_and_job() -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload(private_key)
    ledger = _NonceLedger()
    authorization = activate_harness_authorization(
        raw_qualification=_qualification(payload, private_key),
        release_payload=_release_payload(payload),
        expected_harness=_expected_harness(),
        current_runtime=_runtime(),
        now=NOW,
        consume_nonce=ledger.consume,
    )
    version = _Version(
        datax_release="datax_v202309",
        runtime_sha256=_hash("runtime-tree"),
        reader_plugin_name="mysqlreader",
        reader_plugin_sha256=_hash("mysqlreader-jar"),
        writer_plugin_name="postgresqlwriter",
        writer_plugin_sha256=_hash("postgresqlwriter-jar"),
    )
    _assert_code(
        lambda: bind_execution(
            authorization=replace(authorization, _provenance=object()),
            version=version,
            current_runtime=_runtime(),
            now=NOW,
        ),
        "PHASE_A_GRANT_INVALID",
    )
    for forged_authorization in (
        replace(authorization, payload_root_sha256="0" * 64),
        replace(authorization, qualification_id="forged-qh-0001"),
        replace(
            authorization,
            harness=ExpectedHarness(
                identity="forged-phase-a-harness",
                environment_id="win11-qualification-01",
                environment_manifest_sha256=_hash("windows-environment"),
                harness_version="1.0.0",
            ),
        ),
    ):
        _assert_code(
            lambda forged_authorization=forged_authorization: bind_execution(
                authorization=forged_authorization,
                version=version,
                current_runtime=_runtime(),
                now=NOW,
            ),
            "PHASE_A_GRANT_INVALID",
        )
    binding = bind_execution(
        authorization=authorization,
        version=version,
        current_runtime=_runtime(),
        now=NOW,
    )

    assert authorization.nonce_sha256 != "n" * 32
    assert len(ledger.calls) == 1
    assert binding.payload_root_sha256 == payload["payload_root_sha256"]
    assert binding.issued_at == datetime(2026, 8, 2, 11, 0, tzinfo=UTC)
    assert binding.not_before == datetime(2026, 8, 2, 11, 0, tzinfo=UTC)
    _assert_code(
        lambda: assert_execution_binding(
            binding=replace(binding, _provenance=object()),
            version=version,
            current_runtime=_runtime(),
            expected_harness=_expected_harness(),
            now=NOW,
        ),
        "PHASE_A_GRANT_INVALID",
    )
    _assert_code(
        lambda: assert_execution_binding(
            binding=replace(binding, writer_plugin_sha256="0" * 64),
            version=version,
            current_runtime=_runtime(),
            expected_harness=_expected_harness(),
            now=NOW,
        ),
        "PHASE_A_GRANT_INVALID",
    )
    for malformed in (
        replace(authorization, payload_root_sha256=object()),
        replace(authorization, qualification_id=object()),
        replace(
            authorization,
            harness=ExpectedHarness(
                identity=object(),
                environment_id="win11-qualification-01",
                environment_manifest_sha256=_hash("windows-environment"),
                harness_version="1.0.0",
            ),
        ),
    ):
        _assert_code(
            lambda malformed=malformed: bind_execution(
                authorization=malformed,
                version=version,
                current_runtime=_runtime(),
                now=NOW,
            ),
            "PHASE_A_GRANT_INVALID",
        )
    malformed_binding = replace(binding, reader_plugin_name=[])
    _assert_code(
        lambda: assert_execution_binding(
            binding=malformed_binding,
            version=version,
            current_runtime=_runtime(),
            expected_harness=_expected_harness(),
            now=NOW,
        ),
        "PHASE_A_GRANT_INVALID",
    )
    _assert_code(
        lambda: bind_execution(
            authorization=authorization,
            version=_Version(
                datax_release="datax_v202309",
                runtime_sha256=_AlwaysEqualString("0" * 64),
                reader_plugin_name="mysqlreader",
                reader_plugin_sha256=_hash("mysqlreader-jar"),
                writer_plugin_name="postgresqlwriter",
                writer_plugin_sha256=_hash("postgresqlwriter-jar"),
            ),
            current_runtime=_runtime(),
            now=NOW,
        ),
        "PHASE_A_JOB_VERSION_INVALID",
    )
    _assert_code(
        lambda: bind_execution(
            authorization=authorization,
            version=version,
            current_runtime=PhaseARuntimeIdentity(
                worker_image_digest=f"sha256:{_hash('worker')}",
                datax_release="datax_v202309",
                runtime_sha256=_AlwaysEqualString("0" * 64),
                plugin_sha256s={name: _hash(f"{name}-jar") for name in PLUGIN_NAMES},
            ),
            now=NOW,
        ),
        "PHASE_A_RUNTIME_IDENTITY_INVALID",
    )
    _assert_code(
        lambda: assert_execution_binding(
            binding=binding,
            version=_Version(
                datax_release=_AlwaysEqualString("forged-datax-release"),
                runtime_sha256=_AlwaysEqualString("0" * 64),
                reader_plugin_name=_AlwaysEqualString("forged-reader"),
                reader_plugin_sha256=_AlwaysEqualString("1" * 64),
                writer_plugin_name=_AlwaysEqualString("forged-writer"),
                writer_plugin_sha256=_AlwaysEqualString("2" * 64),
            ),
            current_runtime=_runtime(),
            expected_harness=_expected_harness(),
            now=NOW,
        ),
        "PHASE_A_GRANT_JOB_VERSION_INVALID",
    )
    assert_execution_binding(
        binding=binding,
        version=version,
        current_runtime=_runtime(),
        expected_harness=_expected_harness(),
        now=NOW,
    )


def test_runtime_mismatch_rejects_before_qh_nonce_is_consumed() -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload(private_key)
    ledger = _NonceLedger()
    bad_runtime = _runtime()
    bad_runtime = PhaseARuntimeIdentity(
        worker_image_digest="sha256:" + "0" * 64,
        datax_release=bad_runtime.datax_release,
        runtime_sha256=bad_runtime.runtime_sha256,
        plugin_sha256s=bad_runtime.plugin_sha256s,
    )

    _assert_code(
        lambda: activate_harness_authorization(
            raw_qualification=_qualification(payload, private_key),
            release_payload=_release_payload(payload),
            expected_harness=_expected_harness(),
            current_runtime=bad_runtime,
            now=NOW,
            consume_nonce=ledger.consume,
        ),
        "PHASE_A_RUNTIME_PAYLOAD_MISMATCH",
    )
    assert ledger.calls == []


def test_phase_a_callback_cannot_mutate_harness_or_signed_nonce_values() -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload(private_key)
    expected_harness = _expected_harness()

    def consume(nonce_use: QualificationNonceUse) -> bool:
        for value, attribute, replacement in (
            (nonce_use, "nonce", "x" * 32),
            (expected_harness, "identity", "forged-phase-a-harness"),
        ):
            try:
                object.__setattr__(value, attribute, replacement)
            except AttributeError:
                continue
            raise AssertionError("private callback value unexpectedly accepted mutation")
        return True

    authorization = activate_harness_authorization(
        raw_qualification=_qualification(payload, private_key),
        release_payload=_release_payload(payload),
        expected_harness=expected_harness,
        current_runtime=_runtime(),
        now=NOW,
        consume_nonce=consume,
    )

    assert authorization.harness == expected_harness
    assert authorization.nonce_sha256 == _hash("n" * 32)


def test_private_grant_rechecks_job_runtime_harness_and_expiry() -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload(private_key)
    authorization = activate_harness_authorization(
        raw_qualification=_qualification(payload, private_key),
        release_payload=_release_payload(payload),
        expected_harness=_expected_harness(),
        current_runtime=_runtime(),
        now=NOW,
        consume_nonce=_NonceLedger().consume,
    )
    version = _Version(
        datax_release="datax_v202309",
        runtime_sha256=_hash("runtime-tree"),
        reader_plugin_name="mysqlreader",
        reader_plugin_sha256=_hash("mysqlreader-jar"),
        writer_plugin_name="postgresqlwriter",
        writer_plugin_sha256=_hash("postgresqlwriter-jar"),
    )
    binding = bind_execution(
        authorization=authorization,
        version=version,
        current_runtime=_runtime(),
        now=NOW,
    )
    before_not_before = datetime(2026, 8, 2, 10, 59, 59, tzinfo=UTC)
    _assert_code(
        lambda: bind_execution(
            authorization=authorization,
            version=version,
            current_runtime=_runtime(),
            now=before_not_before,
        ),
        "PHASE_A_QUALIFICATION_NOT_YET_VALID",
    )
    _assert_code(
        lambda: assert_execution_binding(
            binding=binding,
            version=version,
            current_runtime=_runtime(),
            expected_harness=_expected_harness(),
            now=before_not_before,
        ),
        "PHASE_A_GRANT_NOT_YET_VALID",
    )
    wrong_version = _Version(
        **{**version.__dict__, "writer_plugin_sha256": "0" * 64}
    )
    _assert_code(
        lambda: assert_execution_binding(
            binding=binding,
            version=wrong_version,
            current_runtime=_runtime(),
            expected_harness=_expected_harness(),
            now=NOW,
        ),
        "PHASE_A_GRANT_JOB_VERSION_MISMATCH",
    )
    _assert_code(
        lambda: assert_execution_binding(
            binding=binding,
            version=version,
            current_runtime=_runtime(),
            expected_harness=ExpectedHarness(
                identity="different-harness",
                environment_id="win11-qualification-01",
                environment_manifest_sha256=_hash("windows-environment"),
                harness_version="1.0.0",
            ),
            now=NOW,
        ),
        "PHASE_A_GRANT_HARNESS_MISMATCH",
    )
    _assert_code(
        lambda: assert_execution_binding(
            binding=binding,
            version=version,
            current_runtime=_runtime(),
            expected_harness=_expected_harness(),
            now=datetime(2026, 8, 2, 13, 0, tzinfo=UTC),
        ),
        "PHASE_A_GRANT_EXPIRED",
    )


def test_private_grant_rejects_reader_writer_role_confusion_and_bad_qh_window() -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload(private_key)
    authorization = activate_harness_authorization(
        raw_qualification=_qualification(payload, private_key),
        release_payload=_release_payload(payload),
        expected_harness=_expected_harness(),
        current_runtime=_runtime(),
        now=NOW,
        consume_nonce=_NonceLedger().consume,
    )
    role_confused_version = _Version(
        datax_release="datax_v202309",
        runtime_sha256=_hash("runtime-tree"),
        reader_plugin_name="mysqlwriter",
        reader_plugin_sha256=_hash("mysqlwriter-jar"),
        writer_plugin_name="postgresqlreader",
        writer_plugin_sha256=_hash("postgresqlreader-jar"),
    )
    _assert_code(
        lambda: bind_execution(
            authorization=authorization,
            version=role_confused_version,
            current_runtime=_runtime(),
            now=NOW,
        ),
        "PHASE_A_JOB_VERSION_MISMATCH",
    )

    version = _Version(
        datax_release="datax_v202309",
        runtime_sha256=_hash("runtime-tree"),
        reader_plugin_name="mysqlreader",
        reader_plugin_sha256=_hash("mysqlreader-jar"),
        writer_plugin_name="postgresqlwriter",
        writer_plugin_sha256=_hash("postgresqlwriter-jar"),
    )
    binding = bind_execution(
        authorization=authorization,
        version=version,
        current_runtime=_runtime(),
        now=NOW,
    )
    _assert_code(
        lambda: assert_execution_binding(
            binding=replace(binding, not_before=binding.valid_until),
            version=version,
            current_runtime=_runtime(),
            expected_harness=_expected_harness(),
            now=NOW,
        ),
        "PHASE_A_GRANT_INVALID",
    )
