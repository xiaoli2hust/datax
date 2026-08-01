from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fastapi import Request
from starlette.responses import JSONResponse


@dataclass
class ProblemException(Exception):
    status: int
    code: str
    title: str
    detail: str | None = None
    retryable: bool = False
    field_errors: list[dict[str, str]] = field(default_factory=list)
    details: dict[str, Any] | None = None
    headers: dict[str, str] = field(default_factory=dict)


def problem_response(
    request: Request,
    problem: ProblemException,
) -> JSONResponse:
    request_id = str(getattr(request.state, "request_id", "00000000-0000-0000-0000-000000000000"))
    body: dict[str, Any] = {
        "type": (
            "https://datax-enterprise-studio.local/problems/"
            f"{problem.code.lower().replace('_', '-')}"
        ),
        "title": problem.title,
        "status": problem.status,
        "code": problem.code,
        "detail": problem.detail,
        "instance": request.url.path,
        "request_id": request_id,
        "retryable": problem.retryable,
        "field_errors": problem.field_errors,
    }
    if problem.details is not None:
        body["details"] = problem.details
    return JSONResponse(
        status_code=problem.status,
        content=body,
        media_type="application/problem+json",
        headers=problem.headers,
    )
