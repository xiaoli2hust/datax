from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError

import datax_studio.core.service as core_service
import datax_studio.credentials.service as credential_service
import datax_studio.worker.main as worker_main
from datax_studio.worker.main import DynamicWorkerAttestation


def _runtime_settings(tmp_path: Path) -> SimpleNamespace:
    idempotency_key = tmp_path / "idempotency_hmac_key"
    idempotency_key.write_bytes(b"i" * 32)
    return SimpleNamespace(
        database_url="postgresql+psycopg://must-not-be-opened",
        idempotency_hmac_key_file=idempotency_key,
        worker_id="worker-1",
        worker_stale_seconds=20.0,
        resolver_policy_version="des-system-dns-v1",
        egress_policy_version="des-nftables-egress-v1",
        egress_attestation_url="http://127.0.0.1:17990/v1/attestation",
        egress_attestation_timeout_seconds=0.5,
        egress_attestation_max_age_seconds=15.0,
        egress_lease_creation_capability_file=(
            tmp_path / "egress_lease_creation_capability"
        ),
        datasource_connect_timeout_seconds=5,
        datasource_query_timeout_seconds=10,
        kek_keyring_dir=tmp_path,
        kek_active_version="v1",
    )


def test_worker_engine_has_a_fixed_pool_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    expected_engine = object()

    def fake_create_engine(url: str, **kwargs: object) -> object:
        captured["url"] = url
        captured["kwargs"] = kwargs
        return expected_engine

    monkeypatch.setattr(worker_main, "create_engine", fake_create_engine)

    result = worker_main.create_worker_engine(
        SimpleNamespace(database_url="postgresql+psycopg://worker@postgres/datax_studio")
    )

    assert result is expected_engine
    assert captured == {
        "url": "postgresql+psycopg://worker@postgres/datax_studio",
        "kwargs": {
            "pool_pre_ping": True,
            "future": True,
            "pool_size": 4,
            "max_overflow": 0,
            "pool_timeout": 5,
        },
    }


def test_runtime_service_builders_reuse_a_worker_owned_engine(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = _runtime_settings(tmp_path)
    shared_engine = create_engine("sqlite+pysqlite://")

    def unexpected_engine(*_args: object, **_kwargs: object) -> object:
        pytest.fail("the supplied Worker engine must be reused")

    monkeypatch.setattr(core_service, "create_engine", unexpected_engine)
    monkeypatch.setattr(credential_service, "create_engine", unexpected_engine)
    monkeypatch.setattr(
        credential_service.CredentialService,
        "ensure_active_kek_registered",
        lambda _self: None,
    )
    try:
        control = core_service.build_control_service(settings, engine=shared_engine)
        credentials = credential_service.build_credential_service(
            settings,
            engine=shared_engine,
        )
    finally:
        shared_engine.dispose()

    assert control.sessions.kw["bind"] is shared_engine
    assert credentials.sessions.kw["bind"] is shared_engine


def test_dispatcher_initialization_fails_closed_on_database_pressure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def database_unavailable(*_args: object, **_kwargs: object) -> object:
        raise SQLAlchemyError("worker connection budget exhausted")

    monkeypatch.setattr(worker_main, "build_credential_service", database_unavailable)

    dispatchers = worker_main.initialize_worker_dispatchers(
        settings=SimpleNamespace(),
        engine=object(),
        control=object(),
        reconciler=object(),
        runtime_manifest=object(),
    )

    assert dispatchers == (None, None)


def test_worker_main_disposes_the_shared_engine_on_clean_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class DisposableEngine:
        dispose_calls = 0

        def dispose(self) -> None:
            self.dispose_calls += 1

    engine = DisposableEngine()
    control_engines: list[object] = []
    original_stop = worker_main.STOP.is_set()
    worker_main.STOP.set()
    monkeypatch.setattr(
        worker_main,
        "get_settings",
        lambda: SimpleNamespace(
            runtime_manifest_path=Path("/unused/runtime-manifest.json"),
            java_binary_path=Path("/unused/java"),
            egress_attestation_url="http://127.0.0.1:17990/v1/attestation",
            egress_attestation_timeout_seconds=0.5,
            egress_attestation_max_age_seconds=15.0,
            egress_lease_creation_capability_file=Path(
                "/unused/egress_lease_creation_capability"
            ),
            egress_policy_version="des-nftables-egress-v1",
            resolver_policy_version="des-system-dns-v1",
            log_volume_path=Path("/unused/logs"),
            workspace_volume_path=Path("/unused/runs"),
            worker_log_min_free_bytes=64 * 1024 * 1024,
            worker_workspace_min_free_bytes=512 * 1024 * 1024,
        ),
    )
    monkeypatch.setattr(worker_main, "create_worker_engine", lambda _settings: engine)
    monkeypatch.setattr(worker_main.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(
        worker_main.RuntimeIdentity,
        "current",
        lambda: object(),
    )
    monkeypatch.setattr(
        worker_main,
        "run_datax_smoke",
        lambda *_args, **_kwargs: SimpleNamespace(
            ready=False,
            runtime_code="RUNTIME_UNAVAILABLE",
            oracle_code="ORACLE_UNAVAILABLE",
        ),
    )
    monkeypatch.setattr(
        worker_main,
        "build_control_service",
        lambda _settings, *, engine: (
            control_engines.append(engine) or SimpleNamespace(sessions=object())
        ),
    )
    monkeypatch.setattr(worker_main, "WorkerReconciler", lambda **_kwargs: object())
    monkeypatch.setattr(worker_main, "LoopbackEgressAttestationClient", lambda **_kwargs: object())
    monkeypatch.setattr(worker_main, "WorkerStorageVerifier", lambda **_kwargs: object())
    monkeypatch.setattr(
        worker_main,
        "collect_dynamic_worker_attestation",
        lambda **_kwargs: DynamicWorkerAttestation(
            egress=None,
            egress_code="EGRESS_ATTESTATION_UNAVAILABLE",
            storage=None,
            storage_code="STORAGE_ATTESTATION_UNAVAILABLE",
        ),
    )
    monkeypatch.setattr(worker_main, "_upsert_heartbeat", lambda *_args, **_kwargs: None)
    try:
        worker_main.main()
    finally:
        if original_stop:
            worker_main.STOP.set()
        else:
            worker_main.STOP.clear()

    assert control_engines == [engine]
    assert engine.dispose_calls == 1
