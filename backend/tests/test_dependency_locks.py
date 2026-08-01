from __future__ import annotations

import re
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
LOCK_LINE = re.compile(r"^([A-Za-z0-9_.-]+)==([^ ;\\\\]+)")


def _locked_versions(path: Path) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = LOCK_LINE.match(line)
        if match is None:
            continue
        result.setdefault(canonicalize_name(match.group(1)), set()).add(match.group(2))
    return result


def _exact_requirement_versions(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        requirement = Requirement(value)
        versions = [
            specifier.version
            for specifier in requirement.specifier
            if specifier.operator == "=="
        ]
        assert len(requirement.specifier) == 1 and len(versions) == 1, value
        result[canonicalize_name(requirement.name)] = versions[0]
    return result


def test_runtime_and_dev_locks_cover_every_exact_project_dependency() -> None:
    with (BACKEND / "pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream)["project"]
    runtime = _exact_requirement_versions(project["dependencies"])
    development = {
        **runtime,
        **_exact_requirement_versions(project["optional-dependencies"]["dev"]),
    }

    runtime_lock = _locked_versions(BACKEND / "requirements.lock")
    development_lock = _locked_versions(BACKEND / "requirements-dev.lock")
    assert all(runtime_lock.get(name) == {version} for name, version in runtime.items())
    assert all(
        development_lock.get(name) == {version}
        for name, version in development.items()
    )


def test_build_lock_matches_pyproject_build_system() -> None:
    with (BACKEND / "pyproject.toml").open("rb") as stream:
        build_requires = _exact_requirement_versions(
            tomllib.load(stream)["build-system"]["requires"]
        )
    input_requires = [
        line
        for line in (BACKEND / "build-requirements.in")
        .read_text(encoding="utf-8")
        .splitlines()
        if line and not line.startswith("#")
    ]
    assert _exact_requirement_versions(input_requires) == build_requires
    build_lock = _locked_versions(BACKEND / "build-requirements.lock")
    assert all(
        build_lock.get(name) == {version}
        for name, version in build_requires.items()
    )


def test_container_builds_install_only_hash_locked_dependencies() -> None:
    for relative_path in ("backend/Dockerfile", "backend/Dockerfile.worker"):
        document = (ROOT / relative_path).read_text(encoding="utf-8")
        assert document.count("--require-hashes") == 2
        assert "requirements.lock" in document
        assert "build-requirements.lock" in document
        assert "--no-build-isolation --no-deps ." in document
