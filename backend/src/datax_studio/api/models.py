from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class HealthStatus(StrEnum):
    UP = "UP"
    DOWN = "DOWN"
    DEGRADED = "DEGRADED"


class ComponentHealth(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: HealthStatus
    code: str


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: HealthStatus
    version: str
    checked_at: datetime
    components: dict[str, ComponentHealth]
