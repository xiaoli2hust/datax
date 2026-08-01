from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi.testclient import TestClient

from datax_studio.api.app import create_app
from datax_studio.api.models import (
    ComponentHealth,
    HealthResponse,
    HealthStatus,
)
from datax_studio.settings import Settings


class FixedReadiness:
    def __init__(self, status: HealthStatus) -> None:
        self.status = status

    def check(self) -> HealthResponse:
        return HealthResponse(
            status=self.status,
            version="test",
            checked_at=datetime.now(UTC),
            components={
                "runtime": ComponentHealth(
                    status=self.status,
                    code="RUNTIME_OK" if self.status == HealthStatus.UP else "RUNTIME_MISSING",
                )
            },
        )


def test_liveness_is_always_process_only() -> None:
    app = create_app(
        settings=Settings(app_version="test", trusted_host="testserver"),
        readiness=FixedReadiness(HealthStatus.DOWN),
    )
    with TestClient(app) as client:
        response = client.get("/api/v1/health/live")

    assert response.status_code == 200
    assert response.json()["status"] == "UP"
    assert response.json()["components"]["api"]["code"] == "API_RESPONSIVE"
    assert response.headers["X-Request-Id"]
    assert response.headers["Cache-Control"] == "no-store"


def test_readiness_returns_503_without_runtime() -> None:
    app = create_app(
        settings=Settings(app_version="test", trusted_host="testserver"),
        readiness=FixedReadiness(HealthStatus.DOWN),
    )
    with TestClient(app) as client:
        response = client.get("/api/v1/health/ready")

    assert response.status_code == 503
    assert response.json()["status"] == "DOWN"


def test_readiness_returns_200_when_all_components_are_up() -> None:
    app = create_app(
        settings=Settings(app_version="test", trusted_host="testserver"),
        readiness=FixedReadiness(HealthStatus.UP),
    )
    request_id = "018f7e9f-5947-7bb4-889d-25fa817419a4"
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/health/ready",
            headers={"X-Request-Id": request_id},
        )

    assert response.status_code == 200
    assert response.json()["status"] == "UP"
    assert response.headers["X-Request-Id"] == request_id


def test_readiness_returns_200_degraded_for_management_plane() -> None:
    app = create_app(
        settings=Settings(app_version="test", trusted_host="testserver"),
        readiness=FixedReadiness(HealthStatus.DEGRADED),
    )
    with TestClient(app) as client:
        response = client.get("/api/v1/health/ready")

    assert response.status_code == 200
    assert response.json()["status"] == "DEGRADED"


def test_invalid_request_id_is_replaced_with_uuid() -> None:
    app = create_app(
        settings=Settings(app_version="test", trusted_host="testserver"),
        readiness=FixedReadiness(HealthStatus.UP),
    )
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/health/live",
            headers={"X-Request-Id": "not-a-uuid"},
        )

    assert UUID(response.headers["X-Request-Id"])


def test_untrusted_host_is_rejected() -> None:
    app = create_app(
        settings=Settings(app_version="test", trusted_host="127.0.0.1"),
        readiness=FixedReadiness(HealthStatus.UP),
    )
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/health/live",
            headers={"Host": "attacker.example"},
        )

    assert response.status_code == 400


def test_cross_origin_request_is_rejected() -> None:
    app = create_app(
        settings=Settings(app_version="test", trusted_host="testserver"),
        readiness=FixedReadiness(HealthStatus.UP),
    )
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/health/live",
            headers={"Origin": "https://attacker.example"},
        )

    assert response.status_code == 403
    assert response.json()["code"] == "ORIGIN_NOT_ALLOWED"
    assert response.json()["request_id"] == response.headers["X-Request-Id"]
    assert response.headers["Content-Type"].startswith("application/problem+json")
