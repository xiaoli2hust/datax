from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from datax_studio.runtime_manifest import (
    DATAX_SOURCE_COMMIT,
    DATAX_SOURCE_REPOSITORY,
    DATAX_SOURCE_TAG,
    DATAX_SOURCE_TREE,
    check_runtime_manifest,
    run_datax_smoke,
    runtime_tree_sha256,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _java_fixture(tmp_path: Path) -> tuple[Path, str]:
    java = tmp_path / "java-fixture"
    java.write_text(
        "#!/bin/sh\nprintf 'openjdk version \"1.8.0_fixture\"\\n' >&2\n",
        encoding="utf-8",
    )
    java.chmod(0o700)
    result = subprocess.run(
        [str(java), "-version"],
        check=True,
        capture_output=True,
    )
    return java, hashlib.sha256(result.stdout + result.stderr).hexdigest()


def _source() -> dict[str, str]:
    return {
        "repository": DATAX_SOURCE_REPOSITORY,
        "tag": DATAX_SOURCE_TAG,
        "commit": DATAX_SOURCE_COMMIT,
        "tree": DATAX_SOURCE_TREE,
    }


def _smoke_plugins(tmp_path: Path, datax_home: Path) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for name in ("streamreader", "streamwriter"):
        plugin_kind = "reader" if name.endswith("reader") else "writer"
        directory = datax_home / "plugin" / plugin_kind / name
        directory.mkdir(parents=True, exist_ok=True)
        artifact = directory / f"{name}-0.0.1-SNAPSHOT.jar"
        artifact.write_bytes(name.encode())
        result[name] = {
            "path": artifact.relative_to(tmp_path).as_posix(),
            "sha256": _sha256(artifact),
        }
    return result


def _jdbc_drivers(tmp_path: Path, datax_home: Path) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for plugin_name in ("mysqlreader", "mysqlwriter"):
        plugin_kind = "reader" if plugin_name.endswith("reader") else "writer"
        directory = datax_home / "plugin" / plugin_kind / plugin_name / "libs"
        directory.mkdir(parents=True, exist_ok=True)
        artifact = directory / "mysql-connector-j-9.7.0.jar"
        artifact.write_bytes(f"{plugin_name}-connector-j-9.7.0".encode())
        result[f"{plugin_name}_connector_j"] = {
            "path": artifact.relative_to(tmp_path).as_posix(),
            "sha256": _sha256(artifact),
        }
    return result


def _licenses(tmp_path: Path) -> dict[str, dict[str, str]]:
    directory = tmp_path / "licenses"
    directory.mkdir(exist_ok=True)
    result: dict[str, dict[str, str]] = {}
    for name, filename in {
        "apache_2_0": "Apache-2.0.txt",
        "datax_license_notice": "DataX-license-notice.txt",
        "datax_notice": "DataX-NOTICE",
        "lgpl_2_1_or_later": "LGPL-2.1-or-later.txt",
        "mysql_connector_j_9_7_0": "MySQL-Connector-J-9.7.0-LICENSE.txt",
    }.items():
        artifact = directory / filename
        artifact.write_text(name, encoding="utf-8")
        result[name] = {
            "path": artifact.relative_to(tmp_path).as_posix(),
            "sha256": _sha256(artifact),
        }
    return result


def test_missing_manifest_is_explicitly_not_ready(tmp_path: Path) -> None:
    result = check_runtime_manifest(tmp_path / "runtime-manifest.json")

    assert result.ready is False
    assert result.runtime_code == "RUNTIME_MANIFEST_MISSING"


def test_manifest_requires_real_hashed_artifacts(tmp_path: Path) -> None:
    datax_home = tmp_path / "datax"
    datax_home.mkdir()
    (datax_home / "bin").mkdir()
    (datax_home / "bin" / "datax.py").write_bytes(b"runtime fixture")
    (datax_home / "job").mkdir()
    (datax_home / "job" / "job.json").write_text("{}", encoding="utf-8")
    plugin_names = [
        "mysqlreader",
        "mysqlwriter",
        "postgresqlreader",
        "postgresqlwriter",
    ]
    plugins: dict[str, dict[str, str]] = {}
    for name in plugin_names:
        plugin_kind = "reader" if name.endswith("reader") else "writer"
        plugin_directory = datax_home / "plugin" / plugin_kind / name
        plugin_directory.mkdir(parents=True)
        path = plugin_directory / f"{name}-0.0.1-SNAPSHOT.jar"
        path.write_bytes(name.encode())
        plugins[name] = {
            "path": path.relative_to(tmp_path).as_posix(),
            "sha256": _sha256(path),
        }
    oracle_directory = tmp_path / "oracle"
    oracle_directory.mkdir()
    oracle = oracle_directory / "verification_oracle.py"
    oracle.write_bytes(b"oracle")
    java, java_version_hash = _java_fixture(tmp_path)
    smoke_plugins = _smoke_plugins(tmp_path, datax_home)
    jdbc_drivers = _jdbc_drivers(tmp_path, datax_home)

    manifest = {
        "schema_version": "1.0",
        "datax_release": "datax_v202309",
        "source": _source(),
        "runtime_sha256": runtime_tree_sha256(datax_home),
        "datax_home": "datax",
        "datax_entrypoint": {
            "path": "datax/bin/datax.py",
            "sha256": _sha256(datax_home / "bin" / "datax.py"),
        },
        "smoke_job": {
            "path": "datax/job/job.json",
            "sha256": _sha256(datax_home / "job" / "job.json"),
        },
        "plugins": plugins,
        "internal_smoke_plugins": smoke_plugins,
        "jdbc_drivers": jdbc_drivers,
        "licenses": _licenses(tmp_path),
        "java": {
            "path": str(java),
            "sha256": _sha256(java),
            "version_output_sha256": java_version_hash,
        },
        "oracle_schema_version": "1.0",
        "oracle": {
            "path": "oracle/verification_oracle.py",
            "sha256": _sha256(oracle),
        },
    }
    manifest_path = tmp_path / "runtime-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = check_runtime_manifest(manifest_path, expected_java_path=java)

    assert result.ready is True
    assert result.runtime_code == "RUNTIME_OK"
    assert result.oracle_code == "ORACLE_OK"


def test_modified_runtime_tree_blocks_readiness(tmp_path: Path) -> None:
    datax_home = tmp_path / "datax"
    datax_home.mkdir()
    runtime_file = datax_home / "core.jar"
    runtime_file.write_bytes(b"before")
    (datax_home / "bin").mkdir()
    entrypoint = datax_home / "bin" / "datax.py"
    entrypoint.write_text("raise SystemExit(0)\n", encoding="utf-8")
    (datax_home / "job").mkdir()
    smoke_job = datax_home / "job" / "job.json"
    smoke_job.write_text("{}", encoding="utf-8")
    plugin_names = [
        "mysqlreader",
        "mysqlwriter",
        "postgresqlreader",
        "postgresqlwriter",
    ]
    plugins: dict[str, dict[str, str]] = {}
    for name in plugin_names:
        plugin_kind = "reader" if name.endswith("reader") else "writer"
        plugin_directory = datax_home / "plugin" / plugin_kind / name
        plugin_directory.mkdir(parents=True)
        path = plugin_directory / f"{name}-0.0.1-SNAPSHOT.jar"
        path.write_bytes(name.encode())
        plugins[name] = {
            "path": path.relative_to(tmp_path).as_posix(),
            "sha256": _sha256(path),
        }
    oracle_directory = tmp_path / "oracle"
    oracle_directory.mkdir()
    oracle = oracle_directory / "verification_oracle.py"
    oracle.write_bytes(b"oracle")
    java, java_version_hash = _java_fixture(tmp_path)
    smoke_plugins = _smoke_plugins(tmp_path, datax_home)
    jdbc_drivers = _jdbc_drivers(tmp_path, datax_home)
    manifest = {
        "schema_version": "1.0",
        "datax_release": "datax_v202309",
        "source": _source(),
        "runtime_sha256": runtime_tree_sha256(datax_home),
        "datax_home": "datax",
        "datax_entrypoint": {
            "path": "datax/bin/datax.py",
            "sha256": _sha256(entrypoint),
        },
        "smoke_job": {
            "path": "datax/job/job.json",
            "sha256": _sha256(smoke_job),
        },
        "plugins": plugins,
        "internal_smoke_plugins": smoke_plugins,
        "jdbc_drivers": jdbc_drivers,
        "licenses": _licenses(tmp_path),
        "java": {
            "path": str(java),
            "sha256": _sha256(java),
            "version_output_sha256": java_version_hash,
        },
        "oracle_schema_version": "1.0",
        "oracle": {
            "path": "oracle/verification_oracle.py",
            "sha256": _sha256(oracle),
        },
    }
    manifest_path = tmp_path / "runtime-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    runtime_file.write_bytes(b"after")

    result = check_runtime_manifest(manifest_path, expected_java_path=java)

    assert result.ready is False
    assert result.runtime_code == "RUNTIME_TREE_INVALID"
    assert result.oracle_code == "ORACLE_NOT_CHECKED"


def test_extra_legacy_mysql_driver_blocks_readiness(tmp_path: Path) -> None:
    datax_home = tmp_path / "datax"
    datax_home.mkdir()
    (datax_home / "bin").mkdir()
    entrypoint = datax_home / "bin" / "datax.py"
    entrypoint.write_text("raise SystemExit(0)\n", encoding="utf-8")
    (datax_home / "job").mkdir()
    smoke_job = datax_home / "job" / "job.json"
    smoke_job.write_text("{}", encoding="utf-8")
    plugins: dict[str, dict[str, str]] = {}
    for name in (
        "mysqlreader",
        "mysqlwriter",
        "postgresqlreader",
        "postgresqlwriter",
    ):
        plugin_kind = "reader" if name.endswith("reader") else "writer"
        plugin_directory = datax_home / "plugin" / plugin_kind / name
        plugin_directory.mkdir(parents=True)
        artifact = plugin_directory / f"{name}-0.0.1-SNAPSHOT.jar"
        artifact.write_bytes(name.encode())
        plugins[name] = {
            "path": artifact.relative_to(tmp_path).as_posix(),
            "sha256": _sha256(artifact),
        }
    jdbc_drivers = _jdbc_drivers(tmp_path, datax_home)
    legacy = (
        datax_home
        / "plugin/reader/mysqlreader/libs/mysql-connector-java-5.1.47.jar"
    )
    legacy.write_bytes(b"legacy")
    oracle_directory = tmp_path / "oracle"
    oracle_directory.mkdir()
    oracle = oracle_directory / "verification_oracle.py"
    oracle.write_bytes(b"oracle")
    java, java_version_hash = _java_fixture(tmp_path)
    manifest_path = tmp_path / "runtime-manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "datax_release": "datax_v202309",
                "source": _source(),
                "runtime_sha256": runtime_tree_sha256(datax_home),
                "datax_home": "datax",
                "datax_entrypoint": {
                    "path": "datax/bin/datax.py",
                    "sha256": _sha256(entrypoint),
                },
                "smoke_job": {
                    "path": "datax/job/job.json",
                    "sha256": _sha256(smoke_job),
                },
                "plugins": plugins,
                "internal_smoke_plugins": _smoke_plugins(tmp_path, datax_home),
                "jdbc_drivers": jdbc_drivers,
                "licenses": _licenses(tmp_path),
                "java": {
                    "path": str(java),
                    "sha256": _sha256(java),
                    "version_output_sha256": java_version_hash,
                },
                "oracle_schema_version": "1.0",
                "oracle": {
                    "path": "oracle/verification_oracle.py",
                    "sha256": _sha256(oracle),
                },
            }
        ),
        encoding="utf-8",
    )

    result = check_runtime_manifest(manifest_path, expected_java_path=java)

    assert result.ready is False
    assert result.runtime_code == "RUNTIME_ARTIFACT_INVALID"


def test_smoke_probe_executes_hashed_entrypoint(tmp_path: Path) -> None:
    datax_home = tmp_path / "datax"
    datax_home.mkdir()
    (datax_home / "bin").mkdir()
    entrypoint = datax_home / "bin" / "datax.py"
    entrypoint.write_text("raise SystemExit(0)\n", encoding="utf-8")
    (datax_home / "job").mkdir()
    smoke_job = datax_home / "job" / "job.json"
    smoke_job.write_text("{}", encoding="utf-8")
    plugins: dict[str, dict[str, str]] = {}
    for name in (
        "mysqlreader",
        "mysqlwriter",
        "postgresqlreader",
        "postgresqlwriter",
    ):
        plugin_kind = "reader" if name.endswith("reader") else "writer"
        plugin_directory = datax_home / "plugin" / plugin_kind / name
        plugin_directory.mkdir(parents=True)
        artifact = plugin_directory / f"{name}-0.0.1-SNAPSHOT.jar"
        artifact.write_bytes(name.encode())
        plugins[name] = {
            "path": artifact.relative_to(tmp_path).as_posix(),
            "sha256": _sha256(artifact),
        }
    oracle_directory = tmp_path / "oracle"
    oracle_directory.mkdir()
    oracle = oracle_directory / "verification_oracle.py"
    oracle.write_bytes(b"oracle")
    java, java_version_hash = _java_fixture(tmp_path)
    smoke_plugins = _smoke_plugins(tmp_path, datax_home)
    jdbc_drivers = _jdbc_drivers(tmp_path, datax_home)
    manifest_path = tmp_path / "runtime-manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "datax_release": "datax_v202309",
                "source": _source(),
                "runtime_sha256": runtime_tree_sha256(datax_home),
                "datax_home": "datax",
                "datax_entrypoint": {
                    "path": "datax/bin/datax.py",
                    "sha256": _sha256(entrypoint),
                },
                "smoke_job": {
                    "path": "datax/job/job.json",
                    "sha256": _sha256(smoke_job),
                },
                "plugins": plugins,
                "internal_smoke_plugins": smoke_plugins,
                "jdbc_drivers": jdbc_drivers,
                "licenses": _licenses(tmp_path),
                "java": {
                    "path": str(java),
                    "sha256": _sha256(java),
                    "version_output_sha256": java_version_hash,
                },
                "oracle_schema_version": "1.0",
                "oracle": {
                    "path": "oracle/verification_oracle.py",
                    "sha256": _sha256(oracle),
                },
            }
        ),
        encoding="utf-8",
    )

    result = run_datax_smoke(
        manifest_path,
        expected_java_path=java,
    )

    assert result.ready is True
    assert result.runtime_code == "RUNTIME_OK"


def test_modified_artifact_blocks_readiness(tmp_path: Path) -> None:
    manifest_path = tmp_path / "runtime-manifest.json"
    manifest_path.write_text("{}", encoding="utf-8")

    result = check_runtime_manifest(manifest_path)

    assert result.ready is False
    assert result.runtime_code == "RUNTIME_MANIFEST_INVALID"
