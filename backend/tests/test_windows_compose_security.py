from __future__ import annotations

from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).parents[2]


def test_worker_secret_tmpfs_and_resource_limits_are_fixed() -> None:
    compose = yaml.safe_load(
        (REPOSITORY_ROOT / "deploy/windows/compose.yaml").read_text(encoding="utf-8")
    )
    worker = compose["services"]["worker"]

    assert worker["environment"]["DES_SENSITIVE_RUNTIME_ROOT"] == "/tmp/datax-studio-sensitive"
    assert worker["tmpfs"] == ["/tmp:rw,noexec,nosuid,size=256m"]
    assert worker["mem_limit"] == "2g"
    assert worker["cpus"] == 2.0
    assert worker["pids_limit"] == 256
    assert worker["ulimits"]["nofile"] == {"soft": 4096, "hard": 8192}


def test_persistent_workspace_is_not_the_secret_runtime_root() -> None:
    compose = yaml.safe_load(
        (REPOSITORY_ROOT / "deploy/windows/compose.yaml").read_text(encoding="utf-8")
    )
    worker = compose["services"]["worker"]

    assert "workspace-data:/var/lib/datax-studio/runs" in worker["volumes"]
    assert all("/tmp" not in volume for volume in worker["volumes"])
    assert worker["environment"]["DES_WORKSPACE_VOLUME_PATH"] == ("/var/lib/datax-studio/runs")


def test_database_owner_secret_is_not_mounted_into_runtime_services() -> None:
    compose = yaml.safe_load(
        (REPOSITORY_ROOT / "deploy/windows/compose.yaml").read_text(encoding="utf-8")
    )
    services = compose["services"]

    assert services["migrate"]["environment"]["DES_DATABASE_USER"] == "datax_studio"
    assert services["api"]["environment"]["DES_DATABASE_USER"] == "datax_api"
    assert services["worker"]["environment"]["DES_DATABASE_USER"] == "datax_worker"
    assert services["api"]["environment"]["DES_DATABASE_PASSWORD_FILE"] == (
        "/run/secrets/database_password"
    )
    assert services["worker"]["environment"]["DES_DATABASE_PASSWORD_FILE"] == (
        "/run/secrets/database_password"
    )

    def sources(service: str) -> set[str]:
        result: set[str] = set()
        for entry in services[service]["secrets"]:
            result.add(entry if isinstance(entry, str) else entry["source"])
        return result

    assert "postgres_password" in sources("migrate")
    assert "postgres_password" not in sources("api")
    assert "postgres_password" not in sources("worker")
    assert "api_database_password" in sources("api")
    assert "worker_database_password" in sources("worker")
    assert "api_database_password" not in sources("worker")
    assert "worker_database_password" not in sources("api")
