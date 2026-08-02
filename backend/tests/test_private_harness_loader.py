from __future__ import annotations

import base64
import copy
import hashlib
import pickle
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import datax_studio.qualification.private_harness_loader as private_harness_loader
from datax_studio.qualification.private_harness_loader import (
    PrivateHarnessEvidenceConfig,
    PrivateHarnessEvidenceError,
    PrivateHarnessEvidenceFile,
    TrustedPrivateFilesystemRoot,
    load_private_harness_evidence,
)
from datax_studio.release_qualification import ExpectedHarness

NOW = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)
PAYLOAD_DOMAIN = b"DES-RELEASE-PAYLOAD-v1\n"
QUALIFICATION_DOMAIN = b"DES-HARNESS-QUALIFICATION-v1\n"
IMAGE_ROLES = ("api", "egress_guard", "postgres", "web", "worker")
PLUGIN_NAMES = ("mysqlreader", "mysqlwriter", "postgresqlreader", "postgresqlwriter")


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(document: dict[str, object]) -> bytes:
    return rfc8785.dumps(document)


def _artifact(name: str) -> dict[str, str]:
    return {"path": f"evidence/{name}.json", "sha256": _hash(name)}


def _expected_harness() -> ExpectedHarness:
    return ExpectedHarness(
        identity="phase-a-win-harness",
        environment_id="win11-qualification-01",
        environment_manifest_sha256=_hash("windows-environment"),
        harness_version="1.0.0",
    )


def _payload(private_key: Ed25519PrivateKey) -> dict[str, object]:
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    rqa_public_key = Ed25519PrivateKey.generate().public_key().public_bytes(
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
        "rqa_keyring": {
            "keyring_id": "rqa-keyring-0001",
            "keys": [
                {
                    "key_id": "rqa-key-0001",
                    "algorithm": "Ed25519",
                    "public_key_base64": base64.b64encode(rqa_public_key).decode("ascii"),
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


def _qualification_unsigned(
    payload: dict[str, object],
    *,
    valid_until: str = "2026-08-02T13:00:00Z",
) -> dict[str, object]:
    expected = _expected_harness()
    return {
        "schema_version": "1.0",
        "artifact_kind": "HARNESS_QUALIFICATION",
        "qualification_id": "qh-qualification-0001",
        "purpose": "QUALIFICATION_HARNESS",
        "issuer_key_id": "hqa-key-0001",
        "issued_at": "2026-08-02T11:00:00Z",
        "not_before": "2026-08-02T11:00:00Z",
        "valid_until": valid_until,
        "nonce": "nonce-must-never-appear-in-loader-result",
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
) -> bytes:
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


def _write_config(
    tmp_path: Path,
    *,
    payload_raw: bytes,
    qualification_raw: bytes,
) -> PrivateHarnessEvidenceConfig:
    payload_root = tmp_path / "payload-private"
    qualification_root = tmp_path / "qualification-private"
    payload_path = payload_root / "bundle" / "payload.json"
    qualification_path = qualification_root / "grant" / "qualification.json"
    payload_path.parent.mkdir(parents=True)
    qualification_path.parent.mkdir(parents=True)
    payload_path.write_bytes(payload_raw)
    qualification_path.write_bytes(qualification_raw)
    payload_document = _payload_document(payload_raw)
    return PrivateHarnessEvidenceConfig(
        release_payload=PrivateHarnessEvidenceFile(
            root=TrustedPrivateFilesystemRoot(path=payload_root),
            relative_path="bundle/payload.json",
            sha256=_digest(payload_raw),
        ),
        harness_qualification=PrivateHarnessEvidenceFile(
            root=TrustedPrivateFilesystemRoot(path=qualification_root),
            relative_path="grant/qualification.json",
            sha256=_digest(qualification_raw),
        ),
        expected_payload_root_sha256=str(payload_document["payload_root_sha256"]),
        expected_harness=_expected_harness(),
    )


def _payload_document(raw: bytes) -> dict[str, object]:
    import json

    decoded = json.loads(raw)
    assert isinstance(decoded, dict)
    return decoded


def _assert_code(callback: object, expected: str) -> None:
    with pytest.raises(PrivateHarnessEvidenceError) as raised:
        assert callable(callback)
        callback()
    assert raised.value.code == expected


def test_private_loader_reads_only_hash_pinned_bound_evidence_without_raw_nonce(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload(private_key)
    payload_raw = _canonical(payload)
    qualification_raw = _signed_qualification(_qualification_unsigned(payload), private_key)
    config = _write_config(
        tmp_path,
        payload_raw=payload_raw,
        qualification_raw=qualification_raw,
    )

    loaded = load_private_harness_evidence(config=config, now=NOW)

    assert loaded.release_payload.payload_root_sha256 == payload["payload_root_sha256"]
    assert loaded.qualification.qualification_id == "qh-qualification-0001"
    assert loaded.payload_document_sha256 == _digest(payload_raw)
    assert loaded.qualification_document_sha256 == _digest(qualification_raw)
    assert "nonce-must-never-appear-in-loader-result" not in repr(loaded)
    assert not hasattr(loaded, "raw_qualification")
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(loaded)


def test_private_loader_rejects_hash_mismatch_symlink_and_path_escape(tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload(private_key)
    config = _write_config(
        tmp_path,
        payload_raw=_canonical(payload),
        qualification_raw=_signed_qualification(_qualification_unsigned(payload), private_key),
    )

    _assert_code(
        lambda: load_private_harness_evidence(
            config=replace(
                config,
                harness_qualification=replace(
                    config.harness_qualification,
                    sha256="0" * 64,
                ),
            ),
            now=NOW,
        ),
        "PHASE_A_PRIVATE_FILE_HASH_MISMATCH",
    )

    qualification_root = config.harness_qualification.root.path
    original = qualification_root / "grant" / "qualification.json"
    outside = tmp_path / "outside-qualification.json"
    outside.write_bytes(original.read_bytes())
    original.unlink()
    original.symlink_to(outside)
    _assert_code(
        lambda: load_private_harness_evidence(config=config, now=NOW),
        "PHASE_A_PRIVATE_FILE_SYMLINK",
    )
    payload_root_alias = tmp_path / "payload-root-alias"
    payload_root_alias.symlink_to(config.release_payload.root.path, target_is_directory=True)
    _assert_code(
        lambda: load_private_harness_evidence(
            config=replace(
                config,
                release_payload=replace(
                    config.release_payload,
                    root=TrustedPrivateFilesystemRoot(path=payload_root_alias),
                ),
            ),
            now=NOW,
        ),
        "PHASE_A_PRIVATE_FILE_SYMLINK",
    )
    _assert_code(
        lambda: load_private_harness_evidence(
            config=replace(
                config,
                harness_qualification=replace(
                    config.harness_qualification,
                    relative_path="../outside-qualification.json",
                ),
            ),
            now=NOW,
        ),
        "PHASE_A_PRIVATE_PATH_INVALID",
    )


def test_private_loader_rejects_non_regular_oversized_and_unbounded_roots(tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload(private_key)
    payload_raw = _canonical(payload)
    qualification_raw = _signed_qualification(_qualification_unsigned(payload), private_key)
    config = _write_config(
        tmp_path,
        payload_raw=payload_raw,
        qualification_raw=qualification_raw,
    )

    _assert_code(
        lambda: load_private_harness_evidence(
            config=replace(
                config,
                harness_qualification=replace(
                    config.harness_qualification,
                    relative_path="grant",
                ),
            ),
            now=NOW,
        ),
        "PHASE_A_PRIVATE_FILE_NOT_REGULAR",
    )

    oversized = config.release_payload.root.path / "bundle" / "oversized.json"
    oversized.write_bytes(b"x" * (1024 * 1024 + 1))
    _assert_code(
        lambda: load_private_harness_evidence(
            config=replace(
                config,
                release_payload=replace(
                    config.release_payload,
                    relative_path="bundle/oversized.json",
                    sha256=_digest(oversized.read_bytes()),
                ),
            ),
            now=NOW,
        ),
        "PHASE_A_PRIVATE_FILE_TOO_LARGE",
    )
    _assert_code(
        lambda: load_private_harness_evidence(
            config=replace(
                config,
                release_payload=replace(
                    config.release_payload,
                    root=TrustedPrivateFilesystemRoot(path=Path("/")),
                ),
            ),
            now=NOW,
        ),
        "PHASE_A_PRIVATE_ROOT_INVALID",
    )


def test_private_loader_fails_closed_without_safe_descriptor_open_primitives(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload(private_key)
    config = _write_config(
        tmp_path,
        payload_raw=_canonical(payload),
        qualification_raw=_signed_qualification(_qualification_unsigned(payload), private_key),
    )
    monkeypatch.delattr(private_harness_loader.os, "O_NOFOLLOW", raising=False)

    _assert_code(
        lambda: load_private_harness_evidence(config=config, now=NOW),
        "PHASE_A_PRIVATE_NOFOLLOW_UNAVAILABLE",
    )


def test_private_loader_rejects_payload_root_qh_validity_and_binding_drift(tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload(private_key)
    payload_raw = _canonical(payload)
    valid_qh = _signed_qualification(_qualification_unsigned(payload), private_key)
    config = _write_config(
        tmp_path,
        payload_raw=payload_raw,
        qualification_raw=valid_qh,
    )

    _assert_code(
        lambda: load_private_harness_evidence(
            config=replace(config, expected_payload_root_sha256="0" * 64),
            now=NOW,
        ),
        "PHASE_A_PRIVATE_PAYLOAD_REJECTED",
    )

    expired_qh = _signed_qualification(
        _qualification_unsigned(payload, valid_until="2026-08-02T11:30:00Z"),
        private_key,
    )
    expired_config = _write_config(
        tmp_path / "expired",
        payload_raw=payload_raw,
        qualification_raw=expired_qh,
    )
    _assert_code(
        lambda: load_private_harness_evidence(config=expired_config, now=NOW),
        "PHASE_A_PRIVATE_QUALIFICATION_REJECTED",
    )

    drifted_unsigned = _qualification_unsigned(payload)
    binding = drifted_unsigned["payload_binding"]
    assert isinstance(binding, dict)
    binding["payload_root_sha256"] = "0" * 64
    drifted_qh = _signed_qualification(drifted_unsigned, private_key)
    drifted_config = _write_config(
        tmp_path / "binding-drift",
        payload_raw=payload_raw,
        qualification_raw=drifted_qh,
    )
    _assert_code(
        lambda: load_private_harness_evidence(config=drifted_config, now=NOW),
        "PHASE_A_PRIVATE_QUALIFICATION_REJECTED",
    )
