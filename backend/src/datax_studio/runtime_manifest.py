from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from datax_studio.datax_runner import build_datax_command, run_datax_job

SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
GIT_COMMIT_PATTERN = re.compile(r"^[a-f0-9]{40}$")
DATAX_SOURCE_REPOSITORY = "https://github.com/alibaba/DataX.git"
DATAX_SOURCE_TAG = "datax_v202309"
DATAX_SOURCE_COMMIT = "9a1f88751e24314b083a74f1b83ef56d69ce98bd"
DATAX_SOURCE_TREE = "534508f96331c4b9f3737ea4e8294cc56aedc67d"


class RuntimeArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1)
    sha256: str


class DataXSource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repository: str
    tag: str
    commit: str
    tree: str


class JavaRuntime(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1)
    sha256: str
    version_output_sha256: str


class RuntimeManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str
    datax_release: str
    source: DataXSource
    runtime_sha256: str
    datax_home: str
    datax_entrypoint: RuntimeArtifact
    smoke_job: RuntimeArtifact
    plugins: dict[str, RuntimeArtifact]
    internal_smoke_plugins: dict[str, RuntimeArtifact]
    jdbc_drivers: dict[str, RuntimeArtifact]
    licenses: dict[str, RuntimeArtifact]
    java: JavaRuntime
    oracle_schema_version: str
    oracle: RuntimeArtifact

    def validate_contract(self) -> None:
        if self.schema_version != "1.0":
            raise ValueError("unsupported runtime manifest schema")
        if self.datax_release != "datax_v202309":
            raise ValueError("unexpected DataX release")
        if (
            self.source.repository != DATAX_SOURCE_REPOSITORY
            or self.source.tag != DATAX_SOURCE_TAG
            or self.source.commit != DATAX_SOURCE_COMMIT
            or self.source.tree != DATAX_SOURCE_TREE
            or GIT_COMMIT_PATTERN.fullmatch(self.source.commit) is None
            or GIT_COMMIT_PATTERN.fullmatch(self.source.tree) is None
        ):
            raise ValueError("unexpected DataX source identity")
        if self.datax_home != "datax":
            raise ValueError("unexpected DataX home")
        if self.datax_entrypoint.path != "datax/bin/datax.py":
            raise ValueError("unexpected DataX entrypoint")
        if self.smoke_job.path != "datax/job/job.json":
            raise ValueError("unexpected DataX smoke job")
        expected_plugin_paths = {
            "mysqlreader": (
                "datax/plugin/reader/mysqlreader/"
                "mysqlreader-0.0.1-SNAPSHOT.jar"
            ),
            "mysqlwriter": (
                "datax/plugin/writer/mysqlwriter/"
                "mysqlwriter-0.0.1-SNAPSHOT.jar"
            ),
            "postgresqlreader": (
                "datax/plugin/reader/postgresqlreader/"
                "postgresqlreader-0.0.1-SNAPSHOT.jar"
            ),
            "postgresqlwriter": (
                "datax/plugin/writer/postgresqlwriter/"
                "postgresqlwriter-0.0.1-SNAPSHOT.jar"
            ),
        }
        if {
            name: artifact.path for name, artifact in self.plugins.items()
        } != expected_plugin_paths:
            raise ValueError("unexpected DataX plugin artifact path")
        expected_smoke_plugin_paths = {
            "streamreader": (
                "datax/plugin/reader/streamreader/"
                "streamreader-0.0.1-SNAPSHOT.jar"
            ),
            "streamwriter": (
                "datax/plugin/writer/streamwriter/"
                "streamwriter-0.0.1-SNAPSHOT.jar"
            ),
        }
        if {
            name: artifact.path
            for name, artifact in self.internal_smoke_plugins.items()
        } != expected_smoke_plugin_paths:
            raise ValueError("unexpected internal smoke plugin artifact path")
        expected_jdbc_driver_paths = {
            "mysqlreader_connector_j": (
                "datax/plugin/reader/mysqlreader/libs/"
                "mysql-connector-j-9.7.0.jar"
            ),
            "mysqlwriter_connector_j": (
                "datax/plugin/writer/mysqlwriter/libs/"
                "mysql-connector-j-9.7.0.jar"
            ),
        }
        if {
            name: artifact.path for name, artifact in self.jdbc_drivers.items()
        } != expected_jdbc_driver_paths:
            raise ValueError("unexpected JDBC driver artifact path")
        expected_license_paths = {
            "apache_2_0": "licenses/Apache-2.0.txt",
            "datax_license_notice": "licenses/DataX-license-notice.txt",
            "datax_notice": "licenses/DataX-NOTICE",
            "lgpl_2_1_or_later": "licenses/LGPL-2.1-or-later.txt",
            "mysql_connector_j_9_7_0": (
                "licenses/MySQL-Connector-J-9.7.0-LICENSE.txt"
            ),
        }
        if {
            name: artifact.path for name, artifact in self.licenses.items()
        } != expected_license_paths:
            raise ValueError("unexpected runtime license artifact path")
        if self.oracle.path != "oracle/verification_oracle.py":
            raise ValueError("unexpected oracle artifact path")
        if self.oracle_schema_version != "1.0":
            raise ValueError("unexpected oracle schema")
        hashes = [
            self.runtime_sha256,
            self.datax_entrypoint.sha256,
            self.smoke_job.sha256,
            self.java.sha256,
            self.java.version_output_sha256,
            self.oracle.sha256,
        ]
        hashes.extend(item.sha256 for item in self.plugins.values())
        hashes.extend(item.sha256 for item in self.internal_smoke_plugins.values())
        hashes.extend(item.sha256 for item in self.jdbc_drivers.values())
        hashes.extend(item.sha256 for item in self.licenses.values())
        if any(SHA256_PATTERN.fullmatch(item) is None for item in hashes):
            raise ValueError("runtime manifest contains an invalid SHA-256")
        if set(self.plugins) != set(expected_plugin_paths):
            raise ValueError("runtime manifest must contain exactly four certified plugins")


class RuntimeCheck(BaseModel):
    ready: bool
    runtime_code: str
    oracle_code: str


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def runtime_tree_sha256(runtime_home: Path) -> str:
    digest = hashlib.sha256(b"DATAX_RUNTIME_TREE_V1\0")
    files: list[Path] = []
    for candidate in runtime_home.rglob("*"):
        if candidate.is_symlink():
            raise ValueError("runtime tree must not contain symbolic links")
        if candidate.is_file():
            files.append(candidate)
    if not files:
        raise ValueError("runtime tree must contain at least one file")

    for candidate in sorted(files, key=lambda item: item.relative_to(runtime_home).as_posix()):
        relative = candidate.relative_to(runtime_home).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, byteorder="big"))
        digest.update(relative)
        digest.update(bytes.fromhex(file_sha256(candidate)))
    return digest.hexdigest()


def _contained_path(base: Path, relative_path: str) -> Path:
    candidate = base / relative_path
    resolved_base = base.resolve()
    resolved_candidate = candidate.resolve()
    if not resolved_candidate.is_relative_to(resolved_base):
        raise ValueError("runtime manifest path escapes its root")
    return candidate


def _has_exact_mysql_connector_j_set(runtime_home: Path) -> bool:
    expected = {
        (
            runtime_home
            / "plugin/reader/mysqlreader/libs/mysql-connector-j-9.7.0.jar"
        ).resolve(),
        (
            runtime_home
            / "plugin/writer/mysqlwriter/libs/mysql-connector-j-9.7.0.jar"
        ).resolve(),
    }
    actual = {
        candidate.resolve()
        for plugin_kind, plugin_name in (
            ("reader", "mysqlreader"),
            ("writer", "mysqlwriter"),
        )
        for candidate in (
            runtime_home / "plugin" / plugin_kind / plugin_name / "libs"
        ).glob("mysql-connector*.jar")
        if candidate.is_file() and not candidate.is_symlink()
    }
    return actual == expected


def _java_check(java: JavaRuntime, expected_path: Path) -> bool:
    try:
        configured_path = Path(java.path)
        if configured_path.resolve() != expected_path.resolve():
            return False
        if (
            configured_path.is_symlink()
            or not configured_path.is_file()
            or file_sha256(configured_path) != java.sha256
        ):
            return False
        result = subprocess.run(
            [str(configured_path), "-version"],
            check=False,
            capture_output=True,
            timeout=10,
            env={"LANG": "C", "LC_ALL": "C", "PATH": ""},
        )
        version_output = result.stdout + result.stderr
        return (
            result.returncode == 0
            and b'version "1.8.' in version_output
            and hashlib.sha256(version_output).hexdigest()
            == java.version_output_sha256
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return False


def check_runtime_manifest(
    path: Path,
    *,
    expected_java_path: Path | None = None,
) -> RuntimeCheck:
    if not path.is_file():
        return RuntimeCheck(
            ready=False,
            runtime_code="RUNTIME_MANIFEST_MISSING",
            oracle_code="ORACLE_MANIFEST_MISSING",
        )
    try:
        manifest = RuntimeManifest.model_validate_json(path.read_text(encoding="utf-8"))
        manifest.validate_contract()
    except (OSError, UnicodeError, json.JSONDecodeError, ValidationError, ValueError):
        return RuntimeCheck(
            ready=False,
            runtime_code="RUNTIME_MANIFEST_INVALID",
            oracle_code="ORACLE_MANIFEST_INVALID",
        )

    base = path.parent
    try:
        runtime_home = _contained_path(base, manifest.datax_home)
    except (OSError, ValueError):
        return RuntimeCheck(
            ready=False,
            runtime_code="RUNTIME_MANIFEST_INVALID",
            oracle_code="ORACLE_NOT_CHECKED",
        )
    if not runtime_home.is_dir():
        return RuntimeCheck(
            ready=False,
            runtime_code="DATAX_HOME_MISSING",
            oracle_code="ORACLE_NOT_CHECKED",
        )
    if not _has_exact_mysql_connector_j_set(runtime_home):
        return RuntimeCheck(
            ready=False,
            runtime_code="RUNTIME_ARTIFACT_INVALID",
            oracle_code="ORACLE_NOT_CHECKED",
        )
    java_path = expected_java_path or Path(manifest.java.path)
    if not _java_check(manifest.java, java_path):
        return RuntimeCheck(
            ready=False,
            runtime_code="JDK_RUNTIME_INVALID",
            oracle_code="ORACLE_NOT_CHECKED",
        )
    try:
        if runtime_tree_sha256(runtime_home) != manifest.runtime_sha256:
            return RuntimeCheck(
                ready=False,
                runtime_code="RUNTIME_TREE_INVALID",
                oracle_code="ORACLE_NOT_CHECKED",
            )
    except (OSError, UnicodeError, ValueError):
        return RuntimeCheck(
            ready=False,
            runtime_code="RUNTIME_TREE_INVALID",
            oracle_code="ORACLE_NOT_CHECKED",
        )

    artifacts = [
        ("runtime", manifest.datax_entrypoint),
        ("runtime", manifest.smoke_job),
        *[("runtime", artifact) for artifact in manifest.plugins.values()],
        *[
            ("runtime", artifact)
            for artifact in manifest.internal_smoke_plugins.values()
        ],
        *[("runtime", artifact) for artifact in manifest.jdbc_drivers.values()],
        *[("runtime", artifact) for artifact in manifest.licenses.values()],
        ("oracle", manifest.oracle),
    ]
    for artifact_kind, artifact in artifacts:
        try:
            artifact_path = _contained_path(base, artifact.path)
            artifact_valid = (
                not artifact_path.is_symlink()
                and artifact_path.is_file()
                and file_sha256(artifact_path) == artifact.sha256
            )
        except (OSError, ValueError):
            artifact_valid = False
        if not artifact_valid:
            code = (
                "ORACLE_ARTIFACT_INVALID"
                if artifact_kind == "oracle"
                else "RUNTIME_ARTIFACT_INVALID"
            )
            return RuntimeCheck(
                ready=False,
                runtime_code=code if artifact_kind == "runtime" else "RUNTIME_OK",
                oracle_code=code if artifact_kind == "oracle" else "ORACLE_NOT_CHECKED",
            )

    return RuntimeCheck(ready=True, runtime_code="RUNTIME_OK", oracle_code="ORACLE_OK")


def run_datax_smoke(
    manifest_path: Path,
    *,
    expected_java_path: Path | None = None,
    timeout_seconds: float = 120.0,
) -> RuntimeCheck:
    check = check_runtime_manifest(
        manifest_path,
        expected_java_path=expected_java_path,
    )
    if not check.ready:
        return check
    try:
        manifest = RuntimeManifest.model_validate_json(
            manifest_path.read_text(encoding="utf-8")
        )
        base = manifest_path.parent
        runtime_home = _contained_path(base, manifest.datax_home)
        smoke_job = _contained_path(base, manifest.smoke_job.path)
        workspace = Path("/tmp/datax-smoke")
        command = build_datax_command(
            java_path=expected_java_path or Path(manifest.java.path),
            datax_home=runtime_home,
            job_path=smoke_job,
            job_root=runtime_home / "job",
            log_directory=workspace / "logs",
            workspace=workspace,
            job_id="2026073001",
        )
        result = run_datax_job(
            command,
            workspace=workspace,
            timeout_seconds=timeout_seconds,
        )
    except (
        OSError,
        UnicodeError,
        ValueError,
        ValidationError,
        subprocess.SubprocessError,
    ):
        result = None
    if result is None or result.returncode != 0 or result.timed_out:
        return RuntimeCheck(
            ready=False,
            runtime_code="DATAX_SMOKE_FAILED",
            oracle_code="ORACLE_NOT_CHECKED",
        )
    return check
