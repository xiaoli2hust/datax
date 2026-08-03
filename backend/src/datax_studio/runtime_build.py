from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from datax_studio.runtime_manifest import (
    DATAX_SOURCE_COMMIT,
    DATAX_SOURCE_REPOSITORY,
    DATAX_SOURCE_TAG,
    DATAX_SOURCE_TREE,
    DataXSource,
    JavaRuntime,
    RuntimeArtifact,
    RuntimeManifest,
    file_sha256,
    runtime_tree_sha256,
)

PLUGIN_PATHS = {
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
SMOKE_PLUGIN_PATHS = {
    "streamreader": (
        "datax/plugin/reader/streamreader/"
        "streamreader-0.0.1-SNAPSHOT.jar"
    ),
    "streamwriter": (
        "datax/plugin/writer/streamwriter/"
        "streamwriter-0.0.1-SNAPSHOT.jar"
    ),
}
JDBC_DRIVER_PATHS = {
    "mysqlreader_connector_j": (
        "datax/plugin/reader/mysqlreader/libs/mysql-connector-j-9.7.0.jar"
    ),
    "mysqlwriter_connector_j": (
        "datax/plugin/writer/mysqlwriter/libs/mysql-connector-j-9.7.0.jar"
    ),
}


def _assert_exact_jdbc_drivers(root: Path) -> None:
    expected = set(JDBC_DRIVER_PATHS.values())
    actual = {
        path.relative_to(root).as_posix()
        for plugin_kind, plugin_name in (
            ("reader", "mysqlreader"),
            ("writer", "mysqlwriter"),
        )
        for path in (
            root / "datax" / "plugin" / plugin_kind / plugin_name / "libs"
        ).glob("mysql-connector*.jar")
    }
    if actual != expected:
        raise ValueError("runtime must contain only Connector/J 9.7.0")


def _artifact(root: Path, relative_path: str) -> RuntimeArtifact:
    path = root / relative_path
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"required runtime artifact is missing: {relative_path}")
    return RuntimeArtifact(path=relative_path, sha256=file_sha256(path))


def build_manifest(root: Path, java_path: Path) -> RuntimeManifest:
    java_result = subprocess.run(
        [str(java_path), "-version"],
        check=True,
        capture_output=True,
        timeout=10,
        env={"LANG": "C", "LC_ALL": "C", "PATH": ""},
    )
    java_output = java_result.stdout + java_result.stderr
    if b'version "1.8.' not in java_output:
        raise ValueError("release runtime must use JDK 8")
    _assert_exact_jdbc_drivers(root)

    manifest = RuntimeManifest(
        schema_version="1.0",
        datax_release=DATAX_SOURCE_TAG,
        source=DataXSource(
            repository=DATAX_SOURCE_REPOSITORY,
            tag=DATAX_SOURCE_TAG,
            commit=DATAX_SOURCE_COMMIT,
            tree=DATAX_SOURCE_TREE,
        ),
        runtime_sha256=runtime_tree_sha256(root / "datax"),
        datax_home="datax",
        datax_entrypoint=_artifact(root, "datax/bin/datax.py"),
        smoke_job=_artifact(root, "datax/job/job.json"),
        plugins={
            name: _artifact(root, relative_path)
            for name, relative_path in PLUGIN_PATHS.items()
        },
        internal_smoke_plugins={
            name: _artifact(root, relative_path)
            for name, relative_path in SMOKE_PLUGIN_PATHS.items()
        },
        jdbc_drivers={
            name: _artifact(root, relative_path)
            for name, relative_path in JDBC_DRIVER_PATHS.items()
        },
        licenses={
            name: _artifact(root, relative_path)
            for name, relative_path in {
                "apache_2_0": "licenses/Apache-2.0.txt",
                "datax_license_notice": "licenses/DataX-license-notice.txt",
                "datax_notice": "licenses/DataX-NOTICE",
                "lgpl_2_1_or_later": "licenses/LGPL-2.1-or-later.txt",
                "mysql_connector_j_9_7_0": (
                    "licenses/MySQL-Connector-J-9.7.0-LICENSE.txt"
                ),
            }.items()
        },
        java=JavaRuntime(
            path=str(java_path),
            sha256=file_sha256(java_path),
            version_output_sha256=hashlib.sha256(java_output).hexdigest(),
        ),
        oracle_schema_version="1.0",
        oracle=_artifact(root, "oracle/verification_oracle.py"),
    )
    manifest.validate_contract()
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(prog="datax-studio-runtime-build")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--java", type=Path, required=True)
    args = parser.parse_args()

    manifest = build_manifest(args.root, args.java)
    output = args.root / "runtime-manifest.json"
    temporary = output.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(
            manifest.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    temporary.replace(output)


if __name__ == "__main__":
    main()
