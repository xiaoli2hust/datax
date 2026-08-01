from __future__ import annotations

import io
import json
import os
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator, FormatChecker

from datax_studio import system_backup
from datax_studio.system_backup import BackupError

PASSWORD = b"correct horse battery staple"
OTHER_PASSWORD = b"different recovery secret value"
INSTALLATION_ID = "a" * 64
PRODUCT_VERSION = "0.1.0"
MIGRATION_REVISION = "20260731_0014"
EXECUTION_ID = "11111111-1111-4111-8111-111111111111"
ATTEMPT_ID = "22222222-2222-4222-8222-222222222222"
BACKUP_MANIFEST_SCHEMA = (
    Path(__file__).parents[2] / "docs" / "contracts" / "system-backup-manifest.v1.schema.json"
)
RESTORE_JOURNAL_SCHEMA = (
    Path(__file__).parents[2] / "docs" / "contracts" / "system-restore-journal.v1.schema.json"
)


@pytest.fixture(autouse=True)
def lower_test_kdf_cost(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(system_backup, "ARGON2_MEMORY_KIB", 8 * 1024)
    monkeypatch.setattr(system_backup, "ARGON2_TIME_COST", 1)


def _password(value: bytes = PASSWORD) -> bytearray:
    return bytearray(value)


def _metadata_root(tmp_path: Path) -> Path:
    root = tmp_path / "metadata"
    root.mkdir()
    (root / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (root / "images.release.env").write_text(
        "DES_API_IMAGE=example.invalid/api@sha256:" + ("5" * 64) + "\n",
        encoding="ascii",
    )
    (root / "release-manifest.json").write_text(
        json.dumps({"schema_version": "1.1"}),
        encoding="utf-8",
    )
    return root


def _log_root(
    tmp_path: Path,
    content: bytes = b"INFO password=[REDACTED]\nINFO completed\n",
) -> Path:
    root = tmp_path / "source-logs"
    attempt_root = root / EXECUTION_ID
    attempt_root.mkdir(parents=True)
    (attempt_root / f"{ATTEMPT_ID}.log").write_bytes(content)
    return root


def _postgres_dump(tmp_path: Path, content: bytes = b"safe logical rows") -> Path:
    path = tmp_path / system_backup.POSTGRES_DUMP_FILENAME
    path.write_bytes(system_backup.POSTGRES_DUMP_MAGIC + b"\x01\x0f" + content)
    return path


def _secret_root(tmp_path: Path) -> Path:
    root = tmp_path / "source-secrets"
    root.mkdir()
    private_key = Ed25519PrivateKey.generate()
    (root / "postgres_password.txt").write_bytes(b"1" * 64)
    (root / "egress_guard_database_password.txt").write_bytes(b"2" * 64)
    (root / "api_database_password.txt").write_bytes(b"3" * 64)
    (root / "worker_database_password.txt").write_bytes(b"4" * 64)
    (root / "jwt_private_key.pem").write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (root / "jwt_public_key.pem").write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    (root / "refresh_token_hmac_key").write_bytes(b"r" * 32)
    (root / "idempotency_hmac_key").write_bytes(b"i" * 32)
    (root / "credential-kek-v1.key").write_bytes(b"k" * 32)
    return root


def _export_data(
    tmp_path: Path,
) -> tuple[dict[str, object], Path, Path]:
    output = tmp_path / "data-output"
    output.mkdir()
    secret_root = _secret_root(tmp_path)
    result = system_backup.export_data(
        output_dir=output,
        password=_password(),
        installation_id=INSTALLATION_ID,
        product_version=PRODUCT_VERSION,
        migration_revision=MIGRATION_REVISION,
        metadata_root=_metadata_root(tmp_path),
        postgres_dump=_postgres_dump(tmp_path),
        log_root=_log_root(tmp_path),
        secret_root_for_scan=secret_root,
    )
    return result, output / str(result["filename"]), secret_root


def _export_pair(
    tmp_path: Path,
    *,
    data_password: bytes = PASSWORD,
    secrets_password: bytes = OTHER_PASSWORD,
) -> tuple[Path, Path, dict[str, object]]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    data_output = tmp_path / "data-output"
    data_output.mkdir()
    secret_root = _secret_root(tmp_path)
    data_result = system_backup.export_data(
        output_dir=data_output,
        password=_password(data_password),
        installation_id=INSTALLATION_ID,
        product_version=PRODUCT_VERSION,
        migration_revision=MIGRATION_REVISION,
        metadata_root=_metadata_root(tmp_path),
        postgres_dump=_postgres_dump(tmp_path),
        log_root=_log_root(tmp_path),
        secret_root_for_scan=secret_root,
    )
    secrets_output = tmp_path / "secrets-output"
    secrets_output.mkdir()
    secrets_result = system_backup.export_secrets(
        output_dir=secrets_output,
        password=_password(secrets_password),
        installation_id=INSTALLATION_ID,
        product_version=PRODUCT_VERSION,
        migration_revision=MIGRATION_REVISION,
        related_data_backup_id=str(data_result["backup_id"]),
        secret_root=secret_root,
    )
    data_package = data_output / str(data_result["filename"])
    secrets_package = secrets_output / str(secrets_result["filename"])
    manifest = system_backup.inspect_package(data_package, _password(data_password), "DATA")
    return data_package, secrets_package, manifest


def _archive_names(path: Path, password: bytearray, kind: str) -> list[str]:
    try:
        with path.open("rb") as raw:
            encrypted = system_backup.EncryptedReader(raw, password, kind)
            try:
                with tarfile.open(fileobj=encrypted, mode="r|*") as archive:
                    names = [member.name for member in archive]
                encrypted.finish()
                return names
            finally:
                encrypted.close()
    finally:
        system_backup._zeroize(password)


def test_data_backup_contains_only_dump_redacted_logs_and_metadata(
    tmp_path: Path,
) -> None:
    result, package, _ = _export_data(tmp_path)
    assert result["code"] == "BACKUP_CREATED"
    assert result["kind"] == "DATA"
    assert package.is_file()
    assert package.name.endswith(".dxdata")
    assert os.stat(package).st_mode & 0o777 == 0o600

    manifest = system_backup.inspect_package(package, _password(), "DATA")
    assert manifest["backup_id"] == result["backup_id"]
    assert manifest["installation_id"] == INSTALLATION_ID
    assert manifest["migration_revision"] == MIGRATION_REVISION
    assert manifest["database_dump"]["filename"] == "postgres.dump"
    assert manifest["database_dump"]["format"] == "POSTGRESQL_CUSTOM"
    assert [tree["root_name"] for tree in manifest["trees"]] == ["des-log-data"]

    names = set(_archive_names(package, _password(), "DATA"))
    assert names == {
        "manifest.json",
        "metadata/compose.yaml",
        "metadata/images.release.env",
        "metadata/release-manifest.json",
        "database/postgres.dump",
        "logs",
        f"logs/{EXECUTION_ID}",
        f"logs/{EXECUTION_ID}/{ATTEMPT_ID}.log",
    }
    assert not any("workspace" in name or name.endswith("job.json") for name in names)


def test_restore_is_fail_closed_until_journal_and_empty_volume_commit_exist(
    tmp_path: Path,
) -> None:
    _, package, _ = _export_data(tmp_path)
    password = _password()
    with pytest.raises(BackupError) as raised:
        system_backup.restore_package(
            path=package,
            password=password,
            expected_kind="DATA",
            destinations={},
            expected_product_version=PRODUCT_VERSION,
            expected_migration_revision=MIGRATION_REVISION,
        )
    assert raised.value.code == "RESTORE_PAIR_REQUIRED"
    assert password == b"\x00" * len(PASSWORD)


def test_restore_pair_is_authenticated_and_stages_without_claiming_commit(
    tmp_path: Path,
) -> None:
    data_package, secrets_package, manifest = _export_pair(tmp_path)
    staging = tmp_path / "restore-staging"
    staging.mkdir()
    journal = tmp_path / "restore-journal.json"
    data_password = _password()
    secrets_password = _password(OTHER_PASSWORD)

    result = system_backup.stage_restore_pair(
        data_path=data_package,
        secrets_path=secrets_package,
        data_password=data_password,
        secrets_password=secrets_password,
        staging_root=staging,
        journal_path=journal,
        expected_product_version=PRODUCT_VERSION,
        expected_migration_revision=MIGRATION_REVISION,
        expected_release_manifest_sha256=manifest["release_metadata"]["release-manifest.json"][
            "sha256"
        ],
    )

    assert result["code"] == "RESTORE_STAGED_COMMIT_BLOCKED"
    assert result["state"] == "STAGED_COMMIT_BLOCKED"
    assert result["next_required_gate"] == "PG_RESTORE_NEW_EMPTY_VOLUME_AND_ATOMIC_COMMIT"
    assert data_password == b"\x00" * len(PASSWORD)
    assert secrets_password == b"\x00" * len(OTHER_PASSWORD)
    assert (staging / "data" / "database" / "postgres.dump").read_bytes().startswith(b"PGDMP")
    assert (
        staging / "data" / "logs" / EXECUTION_ID / f"{ATTEMPT_ID}.log"
    ).read_bytes() == b"INFO password=[REDACTED]\nINFO completed\n"
    assert (staging / "secrets" / "secrets" / "credential-kek-v1.key").read_bytes() == b"k" * 32
    journal_value = json.loads(journal.read_text(encoding="ascii"))
    assert journal_value["state"] == "STAGED_COMMIT_BLOCKED"
    assert journal_value["authentication"]["algorithm"] == "HMAC-SHA256"
    assert "correct horse battery staple" not in journal.read_text(encoding="ascii")
    schema = json.loads(RESTORE_JOURNAL_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(journal_value)


def test_restore_pair_rejects_wrong_pair_and_release_binding_before_staging(
    tmp_path: Path,
) -> None:
    data_package, secrets_package, manifest = _export_pair(tmp_path / "first")
    _, unrelated_secrets, _ = _export_pair(tmp_path / "second")
    staging = tmp_path / "restore-staging"
    staging.mkdir()
    journal = tmp_path / "restore-journal.json"
    with pytest.raises(BackupError) as raised:
        system_backup.stage_restore_pair(
            data_path=data_package,
            secrets_path=unrelated_secrets,
            data_password=_password(),
            secrets_password=_password(OTHER_PASSWORD),
            staging_root=staging,
            journal_path=journal,
            expected_product_version=PRODUCT_VERSION,
            expected_migration_revision=MIGRATION_REVISION,
            expected_release_manifest_sha256=manifest["release_metadata"]["release-manifest.json"][
                "sha256"
            ],
        )
    assert raised.value.code == "RESTORE_PACKAGE_PAIR_MISMATCH"
    assert not journal.exists()
    assert not any(staging.iterdir())

    with pytest.raises(BackupError) as raised:
        system_backup.stage_restore_pair(
            data_path=data_package,
            secrets_path=secrets_package,
            data_password=_password(),
            secrets_password=_password(OTHER_PASSWORD),
            staging_root=staging,
            journal_path=journal,
            expected_product_version=PRODUCT_VERSION,
            expected_migration_revision=MIGRATION_REVISION,
            expected_release_manifest_sha256="f" * 64,
        )
    assert raised.value.code == "RESTORE_RELEASE_BINDING_MISMATCH"
    assert not journal.exists()


def test_restore_journal_tampering_blocks_resume_and_cleanup(tmp_path: Path) -> None:
    data_package, secrets_package, manifest = _export_pair(tmp_path)
    staging = tmp_path / "restore-staging"
    staging.mkdir()
    journal = tmp_path / "restore-journal.json"
    system_backup.stage_restore_pair(
        data_path=data_package,
        secrets_path=secrets_package,
        data_password=_password(),
        secrets_password=_password(OTHER_PASSWORD),
        staging_root=staging,
        journal_path=journal,
        expected_product_version=PRODUCT_VERSION,
        expected_migration_revision=MIGRATION_REVISION,
        expected_release_manifest_sha256=manifest["release_metadata"]["release-manifest.json"][
            "sha256"
        ],
    )
    value = json.loads(journal.read_text(encoding="ascii"))
    value["state"] = "CLEANED"
    journal.write_text(json.dumps(value), encoding="ascii")

    with pytest.raises(BackupError) as raised:
        system_backup.cleanup_restore_staging(
            staging_root=staging,
            journal_path=journal,
            data_password=_password(),
            secrets_password=_password(OTHER_PASSWORD),
        )
    assert raised.value.code == "RESTORE_JOURNAL_AUTHENTICATION_FAILED"
    assert (staging / "data" / "database" / "postgres.dump").exists()


def test_restore_cleanup_removes_only_authenticated_staging_objects(tmp_path: Path) -> None:
    data_package, secrets_package, manifest = _export_pair(tmp_path)
    staging = tmp_path / "restore-staging"
    staging.mkdir()
    journal = tmp_path / "restore-journal.json"
    system_backup.stage_restore_pair(
        data_path=data_package,
        secrets_path=secrets_package,
        data_password=_password(),
        secrets_password=_password(OTHER_PASSWORD),
        staging_root=staging,
        journal_path=journal,
        expected_product_version=PRODUCT_VERSION,
        expected_migration_revision=MIGRATION_REVISION,
        expected_release_manifest_sha256=manifest["release_metadata"]["release-manifest.json"][
            "sha256"
        ],
    )

    result = system_backup.cleanup_restore_staging(
        staging_root=staging,
        journal_path=journal,
        data_password=_password(),
        secrets_password=_password(OTHER_PASSWORD),
    )
    assert result["code"] == "RESTORE_STAGING_CLEANED"
    assert not any(staging.iterdir())
    assert json.loads(journal.read_text(encoding="ascii"))["state"] == "CLEANED"


def test_restore_rejects_recovery_key_reused_as_runtime_secret(tmp_path: Path) -> None:
    reused = b"1" * 64
    data_package, secrets_package, manifest = _export_pair(
        tmp_path,
        data_password=reused,
    )
    staging = tmp_path / "restore-staging"
    staging.mkdir()
    journal = tmp_path / "restore-journal.json"
    with pytest.raises(BackupError) as raised:
        system_backup.stage_restore_pair(
            data_path=data_package,
            secrets_path=secrets_package,
            data_password=_password(reused),
            secrets_password=_password(OTHER_PASSWORD),
            staging_root=staging,
            journal_path=journal,
            expected_product_version=PRODUCT_VERSION,
            expected_migration_revision=MIGRATION_REVISION,
            expected_release_manifest_sha256=manifest["release_metadata"]["release-manifest.json"][
                "sha256"
            ],
        )
    assert raised.value.code == "RESTORE_KEY_DOMAIN_REUSE_REJECTED"
    journal_value = json.loads(journal.read_text(encoding="ascii"))
    assert journal_value["state"] == "FAILED"


def test_restore_cli_returns_non_success_for_staging_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data_package, secrets_package, manifest = _export_pair(tmp_path)
    staging = tmp_path / "restore-staging"
    staging.mkdir()
    journal = tmp_path / "restore-journal.json"
    monkeypatch.setattr(
        system_backup.sys,
        "stdin",
        SimpleNamespace(buffer=io.BytesIO(PASSWORD + b"\n" + OTHER_PASSWORD + b"\n")),
    )

    exit_code = system_backup.main(
        [
            "stage-restore-pair",
            "--data-input",
            str(data_package),
            "--secrets-input",
            str(secrets_package),
            "--staging-root",
            str(staging),
            "--journal",
            str(journal),
            "--expected-product-version",
            PRODUCT_VERSION,
            "--expected-migration-revision",
            MIGRATION_REVISION,
            "--expected-release-manifest-sha256",
            manifest["release_metadata"]["release-manifest.json"]["sha256"],
        ]
    )

    assert exit_code == 3
    result = json.loads(capsys.readouterr().out)
    assert result["code"] == "RESTORE_STAGED_COMMIT_BLOCKED"


def test_helper_output_rejects_fields_outside_public_contract(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(BackupError) as raised:
        system_backup._emit(
            {
                "schema_version": "1.0",
                "code": "BACKUP_CREATED",
                "kind": "DATA",
                "backup_id": "b" * 32,
                "filename": f"{'b' * 32}.dxdata",
                "package_bytes": 1,
                "package_sha256": "c" * 64,
                "unexpected": "must-not-be-emitted",
            }
        )

    assert raised.value.code == "BACKUP_HELPER_RESPONSE_INVALID"
    assert capsys.readouterr().out == ""


def test_secret_backup_is_separate_and_bound_to_data_id(tmp_path: Path) -> None:
    data_result, _, secret_root = _export_data(tmp_path)
    output = tmp_path / "secret-output"
    output.mkdir()
    secret_result = system_backup.export_secrets(
        output_dir=output,
        password=_password(OTHER_PASSWORD),
        installation_id=INSTALLATION_ID,
        product_version=PRODUCT_VERSION,
        migration_revision=MIGRATION_REVISION,
        related_data_backup_id=str(data_result["backup_id"]),
        secret_root=secret_root,
    )
    package = output / str(secret_result["filename"])
    manifest = system_backup.inspect_package(package, _password(OTHER_PASSWORD), "SECRETS")
    assert manifest["related_data_backup_id"] == data_result["backup_id"]
    assert [tree["root_name"] for tree in manifest["trees"]] == ["secrets"]
    assert all(
        name == "manifest.json" or name.startswith("secrets")
        for name in _archive_names(
            package,
            _password(OTHER_PASSWORD),
            "SECRETS",
        )
    )


def test_exported_manifests_match_machine_contract(tmp_path: Path) -> None:
    schema = json.loads(BACKUP_MANIFEST_SCHEMA.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    data_result, data_package, secret_root = _export_data(tmp_path)
    data_manifest = system_backup.inspect_package(
        data_package,
        _password(),
        "DATA",
    )
    validator.validate(data_manifest)

    output = tmp_path / "secret-output"
    output.mkdir()
    secret_result = system_backup.export_secrets(
        output_dir=output,
        password=_password(OTHER_PASSWORD),
        installation_id=INSTALLATION_ID,
        product_version=PRODUCT_VERSION,
        migration_revision=MIGRATION_REVISION,
        related_data_backup_id=str(data_result["backup_id"]),
        secret_root=secret_root,
    )
    secret_manifest = system_backup.inspect_package(
        output / str(secret_result["filename"]),
        _password(OTHER_PASSWORD),
        "SECRETS",
    )
    validator.validate(secret_manifest)


def test_internal_manifest_validation_matches_strict_contract(tmp_path: Path) -> None:
    _, data_package, _ = _export_data(tmp_path)
    manifest = system_backup.inspect_package(data_package, _password(), "DATA")

    manifest["trees"][0]["file_count"] = False
    with pytest.raises(BackupError, match="备份树证据"):
        system_backup._validate_manifest(manifest, "DATA")

    manifest["trees"][0]["file_count"] = 1
    manifest["created_at"] = manifest["created_at"].removesuffix("Z") + "+00:00"
    with pytest.raises(BackupError, match="UTC Z"):
        system_backup._validate_manifest(manifest, "DATA")

    with pytest.raises(BackupError, match="不安全路径"):
        system_backup._safe_tar_name("logs//non-canonical.log")


@pytest.mark.parametrize("mutation", ["wrong-password", "tamper", "truncate", "trailing"])
def test_backup_authentication_fails_closed(tmp_path: Path, mutation: str) -> None:
    _, package, _ = _export_data(tmp_path)
    candidate = tmp_path / f"{mutation}.dxdata"
    value = bytearray(package.read_bytes())
    password = _password()
    if mutation == "wrong-password":
        candidate.write_bytes(value)
        password = _password(OTHER_PASSWORD)
    elif mutation == "tamper":
        value[-20] ^= 0x40
        candidate.write_bytes(value)
    elif mutation == "truncate":
        candidate.write_bytes(value[:-1])
    else:
        candidate.write_bytes(value + b"x")
    with pytest.raises(BackupError):
        system_backup.inspect_package(candidate, password, "DATA")


def test_export_rejects_log_links_and_unknown_secret_files(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    logs = _log_root(tmp_path)
    (logs / "escape").symlink_to(tmp_path)
    secrets = _secret_root(tmp_path)
    with pytest.raises(BackupError, match="符号链接"):
        system_backup.export_data(
            output_dir=output,
            password=_password(),
            installation_id=INSTALLATION_ID,
            product_version=PRODUCT_VERSION,
            migration_revision=MIGRATION_REVISION,
            metadata_root=_metadata_root(tmp_path),
            postgres_dump=_postgres_dump(tmp_path),
            log_root=logs,
            secret_root_for_scan=secrets,
        )
    assert not any(output.iterdir())

    (secrets / "unrecognized-secret").write_bytes(b"x" * 32)
    with pytest.raises(BackupError, match="未识别"):
        system_backup.export_secrets(
            output_dir=output,
            password=_password(),
            installation_id=INSTALLATION_ID,
            product_version=PRODUCT_VERSION,
            migration_revision=MIGRATION_REVISION,
            related_data_backup_id="1" * 32,
            secret_root=secrets,
        )
    assert not any(output.iterdir())


def test_export_rejects_job_json_by_fixed_log_allowlist(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    logs = _log_root(tmp_path)
    (logs / "job.json").write_text('{"job":{"content":[]}}', encoding="utf-8")
    with pytest.raises(BackupError) as raised:
        system_backup.export_data(
            output_dir=output,
            password=_password(),
            installation_id=INSTALLATION_ID,
            product_version=PRODUCT_VERSION,
            migration_revision=MIGRATION_REVISION,
            metadata_root=_metadata_root(tmp_path),
            postgres_dump=_postgres_dump(tmp_path),
            log_root=logs,
            secret_root_for_scan=_secret_root(tmp_path),
        )
    assert raised.value.code == "BACKUP_DATA_ALLOWLIST_REJECTED"
    assert not any(output.iterdir())


def test_export_rejects_reused_database_role_passwords(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    secrets = _secret_root(tmp_path)
    (secrets / "worker_database_password.txt").write_bytes(b"3" * 64)
    with pytest.raises(BackupError, match="域分离"):
        system_backup.export_secrets(
            output_dir=output,
            password=_password(),
            installation_id=INSTALLATION_ID,
            product_version=PRODUCT_VERSION,
            migration_revision=MIGRATION_REVISION,
            related_data_backup_id="1" * 32,
            secret_root=secrets,
        )
    assert not any(output.iterdir())


@pytest.mark.parametrize(
    "content",
    [
        b'INFO password="plaintext-password"\n',
        b"INFO exact-secret=" + (b"k" * 32) + b"\n",
        b'{"job":{"content":[{"reader":{},"writer":{}}]}}\n',
        b"-----BEGIN PRIVATE KEY-----\nunknown\n",
    ],
)
def test_export_rejects_unredacted_or_runtime_config_log_content(
    tmp_path: Path,
    content: bytes,
) -> None:
    output = tmp_path / "output"
    output.mkdir()
    with pytest.raises(BackupError) as raised:
        system_backup.export_data(
            output_dir=output,
            password=_password(),
            installation_id=INSTALLATION_ID,
            product_version=PRODUCT_VERSION,
            migration_revision=MIGRATION_REVISION,
            metadata_root=_metadata_root(tmp_path),
            postgres_dump=_postgres_dump(tmp_path),
            log_root=_log_root(tmp_path, content),
            secret_root_for_scan=_secret_root(tmp_path),
        )
    assert raised.value.code in {
        "BACKUP_DATA_ALLOWLIST_REJECTED",
        "BACKUP_SECRET_LEAK_DETECTED",
    }
    assert not any(output.iterdir())


def test_export_rejects_secret_leaked_into_postgres_dump(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    with pytest.raises(BackupError) as raised:
        system_backup.export_data(
            output_dir=output,
            password=_password(),
            installation_id=INSTALLATION_ID,
            product_version=PRODUCT_VERSION,
            migration_revision=MIGRATION_REVISION,
            metadata_root=_metadata_root(tmp_path),
            postgres_dump=_postgres_dump(tmp_path, b"row-" + (b"k" * 32)),
            log_root=_log_root(tmp_path),
            secret_root_for_scan=_secret_root(tmp_path),
        )
    assert raised.value.code == "BACKUP_SECRET_LEAK_DETECTED"
    assert not any(output.iterdir())


def test_export_rejects_non_custom_pg_dump(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    dump = tmp_path / "plain.sql"
    dump.write_text("select 1;", encoding="utf-8")
    with pytest.raises(BackupError) as raised:
        system_backup.export_data(
            output_dir=output,
            password=_password(),
            installation_id=INSTALLATION_ID,
            product_version=PRODUCT_VERSION,
            migration_revision=MIGRATION_REVISION,
            metadata_root=_metadata_root(tmp_path),
            postgres_dump=dump,
            log_root=_log_root(tmp_path),
            secret_root_for_scan=_secret_root(tmp_path),
        )
    assert raised.value.code == "BACKUP_DUMP_INVALID"
    assert not any(output.iterdir())


def test_restore_commands_are_not_exposed_by_helper_cli() -> None:
    with pytest.raises(SystemExit):
        system_backup._parser().parse_args(["restore-data"])
    with pytest.raises(SystemExit):
        system_backup._parser().parse_args(["restore-secrets"])


def test_test_profile_preserves_chunk_and_argon2_parameter_shape() -> None:
    assert system_backup.ARGON2_MEMORY_KIB == 8 * 1024
    assert system_backup.ARGON2_TIME_COST == 1
    assert system_backup.ARGON2_PARALLELISM == 1
    assert system_backup.CHUNK_SIZE == 1024 * 1024
