from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from urllib.parse import quote_plus

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from datax_studio.egress_attestation import (
    POLICY_ENGINE_VERSION,
    RESOLVER_POLICY_VERSION,
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="DES_",
        case_sensitive=False,
        extra="ignore",
    )

    app_version: str = "0.1.0-dev"
    app_environment: str = "development"
    database_schema_revision: str = "20260802_0022"
    ui_origin: str = "http://127.0.0.1:17860"
    trusted_host: str = "127.0.0.1"
    database_host: str = "postgres"
    database_port: int = 5432
    database_name: str = "datax_studio"
    database_user: str = "datax_studio"
    database_password_file: Path = Path("/run/secrets/postgres_password")
    jwt_private_key_file: Path = Path("/run/secrets/jwt_private_key.pem")
    jwt_public_key_file: Path = Path("/run/secrets/jwt_public_key.pem")
    refresh_token_hmac_key_file: Path = Path("/run/secrets/refresh_token_hmac_key")
    idempotency_hmac_key_file: Path = Path("/run/secrets/idempotency_hmac_key")
    kek_keyring_dir: Path = Path("/run/secrets")
    kek_active_version: str = "v1"
    resolver_policy_version: str = RESOLVER_POLICY_VERSION
    egress_policy_version: str = POLICY_ENGINE_VERSION
    egress_attestation_url: str = "http://127.0.0.1:17990/v1/attestation"
    egress_attestation_timeout_seconds: float = Field(default=0.5, gt=0, le=5)
    egress_attestation_max_age_seconds: float = Field(default=15, gt=0, le=30)
    egress_lease_creation_capability_file: Path = Path(
        "/run/secrets/egress_lease_creation_capability"
    )
    datasource_connect_timeout_seconds: int = Field(default=5, ge=1, le=30)
    datasource_query_timeout_seconds: int = Field(default=10, ge=1, le=60)
    # ADR-0014: V1 is one API process.  External datasource work is admitted
    # locally before it can consume DNS, egress, decrypt, or connector budget.
    # The per-organization and per-datasource limits are deliberately fixed at
    # one; widening them is an architecture/security decision, not a deployment
    # tuning knob.
    datasource_operation_max_global_in_flight: int = Field(default=4, ge=1, le=16)
    datasource_operation_max_organization_in_flight: int = Field(default=1, ge=1, le=1)
    datasource_operation_max_datasource_in_flight: int = Field(default=1, ge=1, le=1)
    datasource_operation_test_cooldown_seconds: float = Field(
        default=60.0,
        ge=1.0,
        le=300.0,
    )
    datasource_operation_deadline_seconds: float = Field(
        default=30.0,
        ge=5.0,
        le=120.0,
    )
    datasource_operation_retention_seconds: float = Field(
        default=300.0,
        ge=60.0,
        le=3600.0,
    )
    datasource_operation_max_retained_organizations: int = Field(
        default=64,
        ge=1,
        le=1024,
    )
    datasource_operation_max_retained_datasources: int = Field(
        default=256,
        ge=1,
        le=4096,
    )
    jwt_issuer: str = "datax-enterprise-studio"
    jwt_audience: str = "datax-enterprise-studio-local"
    access_token_seconds: int = Field(default=900, ge=60, le=3600)
    refresh_token_days: int = Field(default=30, ge=1, le=90)
    login_failure_limit: int = Field(default=5, ge=3, le=20)
    login_lock_seconds: int = Field(default=900, ge=60, le=86400)
    login_admission_burst: int = Field(default=5, ge=1, le=20)
    login_admission_rate_per_minute: int = Field(default=5, ge=1, le=60)
    # ADR-0012 fixes V1 to one API process and one bounded password-verification
    # slot.  Widening this needs an ADR plus a capacity/security review, not an
    # environment-only tuning change.
    login_admission_max_in_flight: int = Field(default=1, ge=1, le=1)
    readiness_cache_seconds: float = Field(default=1.0, ge=0.1, le=5.0)
    audit_integrity_full_replay_max_age_seconds: float = Field(
        default=60.0,
        ge=10.0,
        le=300.0,
    )
    audit_integrity_replay_timeout_seconds: float = Field(
        default=30.0,
        ge=1.0,
        le=60.0,
    )
    runtime_manifest_path: Path = Path("/opt/datax/runtime-manifest.json")
    java_binary_path: Path = Path("/opt/java/openjdk/bin/java")
    log_volume_path: Path = Path("/var/lib/datax-studio/logs")
    workspace_volume_path: Path = Path("/var/lib/datax-studio/runs")
    sensitive_runtime_root: Path = Path("/tmp/datax-studio-sensitive")
    worker_id: str = "worker-1"
    worker_heartbeat_seconds: float = Field(default=5.0, ge=1.0, le=60.0)
    worker_stale_seconds: float = Field(default=20.0, ge=5.0, le=300.0)
    worker_lease_seconds: int = Field(default=30, ge=5, le=300)
    worker_control_poll_seconds: float = Field(default=1.0, ge=0.2, le=10.0)
    worker_log_min_free_bytes: int = Field(
        default=64 * 1024 * 1024,
        ge=16 * 1024 * 1024,
        le=1024 * 1024 * 1024 * 1024,
    )
    worker_workspace_min_free_bytes: int = Field(
        default=512 * 1024 * 1024,
        ge=64 * 1024 * 1024,
        le=1024 * 1024 * 1024 * 1024,
    )
    execution_log_limit_bytes: int = Field(
        default=4 * 1024 * 1024,
        ge=1024,
        le=64 * 1024 * 1024,
    )
    execution_log_line_limit_bytes: int = Field(
        default=16 * 1024,
        ge=128,
        le=1024 * 1024,
    )
    log_retention_days: int = Field(default=30, ge=30, le=365)
    execution_retention_days: int = Field(default=365, ge=365, le=3650)
    audit_retention_days: int = Field(default=730, ge=730, le=7300)
    idempotency_retention_hours: int = Field(default=24, ge=24, le=720)
    retention_batch_size: int = Field(default=500, ge=1, le=5000)
    log_export_limit_bytes: int = Field(
        default=100 * 1024 * 1024,
        ge=1024,
        le=100 * 1024 * 1024,
    )

    @property
    def database_password(self) -> str:
        password = self.database_password_file.read_text(encoding="utf-8").strip()
        if not password:
            raise ValueError("database password file is empty")
        return password

    @property
    def database_url(self) -> str:
        return (
            "postgresql+psycopg://"
            f"{quote_plus(self.database_user)}:{quote_plus(self.database_password)}"
            f"@{self.database_host}:{self.database_port}/{self.database_name}"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
