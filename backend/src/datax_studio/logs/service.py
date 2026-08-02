from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from uuid import UUID, uuid4

import rfc8785
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from datax_studio.api.problems import ProblemException
from datax_studio.audit_integrity import advance_audit_chain_watermark
from datax_studio.auth.db import AuditEvent, Organization, User
from datax_studio.auth.security import ensure_aware, utc_now
from datax_studio.auth.service import AuditContext, Principal
from datax_studio.core.db import Execution
from datax_studio.core.schemas import ClaimedExecution
from datax_studio.core.service import ControlService
from datax_studio.logs.db import ExecutionLogChunk, ExecutionLogGap
from datax_studio.logs.schemas import (
    LogDownload,
    LogGap,
    LogLine,
    LogPage,
)
from datax_studio.settings import Settings
from datax_studio.worker.process import ProcessLogResult

_CURSOR_DOMAIN = b"DataXEnterpriseStudio\x00ExecutionLogCursor\x00v1\x00"
_TRUNCATION_REASONS = frozenset({"LINE_LIMIT", "EXECUTION_LIMIT", "RING_EVICTION"})
_LEVEL_PATTERN = re.compile(
    r"(?:^|[\s\[])"
    r"(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|SEVERE|FATAL)"
    r"(?:[\s\]:-]|$)",
    re.IGNORECASE,
)
_MAX_MESSAGE_CHARACTERS = 16384


@dataclass(frozen=True)
class _StoredBody:
    body: bytes
    storage_key: str
    sha256: str


class _BodyProblem(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ExecutionLogService:
    """Own the index for persisted output that has already been redacted.

    This service never accepts or opens a raw-log path. The Worker writes its
    bounded redactor directly beneath the dedicated log volume and passes only
    the redacted `ProcessLogResult` here.
    """

    def __init__(
        self,
        *,
        settings: Settings,
        control: ControlService,
    ) -> None:
        self.settings = settings
        self.control = control

    def persist_claimed_process_log(
        self,
        *,
        claim: ClaimedExecution,
        result: ProcessLogResult,
    ) -> None:
        self._validate_process_accounting(result)
        with self.control.sessions.begin() as session:
            now = self.control._database_now(session)  # noqa: SLF001
            execution, attempt = self.control._current_fenced_attempt(  # noqa: SLF001
                session,
                claim=claim,
                now=now,
                lock=True,
            )
            already_indexed = session.scalar(
                select(ExecutionLogChunk.id).where(
                    ExecutionLogChunk.execution_id == execution.id,
                    ExecutionLogChunk.attempt_id == attempt.id,
                )
            )
            already_gapped = session.scalar(
                select(ExecutionLogGap.id).where(
                    ExecutionLogGap.execution_id == execution.id,
                    ExecutionLogGap.attempt_id == attempt.id,
                )
            )
            if already_indexed is not None or already_gapped is not None:
                return

            first_sequence = (
                session.scalar(
                    select(func.max(ExecutionLogChunk.last_sequence)).where(
                        ExecutionLogChunk.execution_id == execution.id
                    )
                )
                or 0
            ) + 1
            body_problem: str | None = None
            stored: _StoredBody | None = None
            try:
                stored = self._load_worker_redacted_body(
                    result.path,
                    execution_id=execution.id,
                    attempt_id=attempt.id,
                    expected_size=result.stored_bytes,
                )
            except _BodyProblem as exc:
                body_problem = exc.reason
                self._discard_safe_log_path(
                    result.path,
                    execution_id=execution.id,
                    attempt_id=attempt.id,
                )

            effective_stored_bytes = 0
            if stored is not None and stored.body:
                line_count = _display_line_count(stored.body)
                if line_count <= 0:
                    raise RuntimeError("non-empty UTF-8 log has no display line")
                session.add(
                    ExecutionLogChunk(
                        id=uuid4(),
                        execution_id=execution.id,
                        attempt_id=attempt.id,
                        chunk_no=1,
                        first_sequence=first_sequence,
                        last_sequence=first_sequence + line_count - 1,
                        storage_key=stored.storage_key,
                        byte_size=len(stored.body),
                        sha256=stored.sha256,
                        redaction_rules_version="1.0",
                        contains_truncated_line=any(
                            gap.reason == "LINE_LIMIT" for gap in result.gaps
                        ),
                        raw_received_bytes=result.raw_received_bytes,
                        redacted_received_bytes=(result.redacted_received_bytes),
                        stored_bytes=len(stored.body),
                        dropped_bytes=result.dropped_bytes,
                        body_available=True,
                        created_at=now,
                        expires_at=now + timedelta(days=self.settings.log_retention_days),
                        deleted_at=None,
                    )
                )
                effective_stored_bytes = len(stored.body)

            gaps = [
                (
                    gap.reason,
                    0,
                    gap.dropped_bytes,
                    0,
                    gap.dropped_bytes,
                )
                for gap in result.gaps
            ]
            if body_problem is not None:
                # Original truncation gaps remain explicit. The storage/decode
                # gap accounts only for bytes that had survived those policies.
                gaps.append(
                    (
                        body_problem,
                        0,
                        result.stored_bytes,
                        0,
                        result.stored_bytes,
                    )
                )
            self._append_gaps(
                session,
                execution_id=execution.id,
                attempt_id=attempt.id,
                first_sequence=first_sequence,
                gaps=gaps,
                detected_at=now,
            )
            execution.log_raw_received_bytes += result.raw_received_bytes
            execution.log_redacted_received_bytes += result.redacted_received_bytes
            execution.log_stored_bytes += effective_stored_bytes
            execution.log_dropped_bytes += result.redacted_received_bytes - effective_stored_bytes
            execution.log_incomplete = execution.log_incomplete or bool(gaps)
            truncated = any(reason in _TRUNCATION_REASONS for reason, *_ in gaps)
            execution.log_truncated = execution.log_truncated or truncated
            if truncated and execution.first_truncated_sequence is None:
                execution.first_truncated_sequence = first_sequence
            execution.datax_finished_at = now
            execution.state_version += 1

    def get_page(
        self,
        *,
        principal: Principal,
        execution_id: UUID,
        cursor: str | None,
        limit: int,
        stream: str | None,
    ) -> LogPage:
        start_sequence = (
            self._decode_cursor(
                cursor,
                actor_id=principal.user_id,
                execution_id=execution_id,
                stream=stream,
            )
            if cursor is not None
            else 1
        )
        with self.control.sessions.begin() as session:
            execution = self.control._visible_execution(  # noqa: SLF001
                session,
                principal,
                execution_id,
            )
            now = self.control._database_now(session)  # noqa: SLF001
            chunks = list(
                session.scalars(
                    select(ExecutionLogChunk)
                    .where(ExecutionLogChunk.execution_id == execution.id)
                    .order_by(ExecutionLogChunk.first_sequence)
                )
            )
            expires_at = self._expires_at(execution, chunks)
            if now >= expires_at:
                self._expired()

            rendered: list[LogLine] = []
            maximum_sequence = max(
                (chunk.last_sequence for chunk in chunks),
                default=0,
            )
            for chunk in chunks:
                if (
                    not chunk.body_available
                    or ensure_aware(chunk.expires_at) <= now
                    or chunk.last_sequence < start_sequence
                ):
                    continue
                try:
                    body = self._load_indexed_body(chunk)
                    lines = list(self._render_chunk(chunk, body))
                except _BodyProblem as exc:
                    self._mark_chunk_unavailable(
                        session,
                        execution=execution,
                        chunk=chunk,
                        now=now,
                        reason=exc.reason,
                    )
                    continue
                if len(lines) != chunk.last_sequence - chunk.first_sequence + 1:
                    self._mark_chunk_unavailable(
                        session,
                        execution=execution,
                        chunk=chunk,
                        now=now,
                        reason="STORAGE_FAILURE",
                    )
                    continue
                for line in lines:
                    if line.sequence < start_sequence:
                        continue
                    if stream is not None and line.stream != stream:
                        continue
                    rendered.append(line)
                    if len(rendered) > limit:
                        break
                if len(rendered) > limit:
                    break

            has_more = len(rendered) > limit
            items = rendered[:limit]
            if items:
                next_sequence = items[-1].sequence + 1
            elif maximum_sequence >= start_sequence:
                next_sequence = maximum_sequence + 1
            else:
                next_sequence = start_sequence
            eof = not has_more and next_sequence > maximum_sequence
            gaps = list(
                session.scalars(
                    select(ExecutionLogGap)
                    .where(ExecutionLogGap.execution_id == execution.id)
                    .order_by(
                        ExecutionLogGap.detected_at,
                        ExecutionLogGap.gap_no,
                        ExecutionLogGap.id,
                    )
                )
            )
            redaction_versions = {
                chunk.redaction_rules_version for chunk in chunks if chunk.body_available
            }
            redaction_version = (
                next(iter(redaction_versions)) if len(redaction_versions) == 1 else "1.0"
            )
            return LogPage(
                items=items,
                next_cursor=self._encode_cursor(
                    actor_id=principal.user_id,
                    execution_id=execution.id,
                    next_sequence=next_sequence,
                    stream=stream,
                ),
                eof=eof,
                redaction_rules_version=redaction_version,
                truncated=execution.log_truncated,
                incomplete=execution.log_incomplete,
                raw_received_bytes=execution.log_raw_received_bytes,
                redacted_received_bytes=(execution.log_redacted_received_bytes),
                stored_bytes=execution.log_stored_bytes,
                reason=_truncation_reason(gaps),
                dropped_bytes=execution.log_dropped_bytes,
                first_truncated_sequence=(execution.first_truncated_sequence),
                gap_count=len(gaps),
                gaps=[self._gap_response(gap) for gap in gaps[:1000]],
                expires_at=expires_at,
            )

    def download(
        self,
        *,
        principal: Principal,
        execution_id: UUID,
        audit: AuditContext,
    ) -> LogDownload:
        denial: ProblemException | None = None
        result: LogDownload | None = None
        try:
            with self.control.sessions.begin() as session:
                execution = self.control._visible_execution(  # noqa: SLF001
                    session,
                    principal,
                    execution_id,
                )
                now = self.control._database_now(session)  # noqa: SLF001
                chunks = list(
                    session.scalars(
                        select(ExecutionLogChunk)
                        .where(ExecutionLogChunk.execution_id == execution.id)
                        .order_by(ExecutionLogChunk.first_sequence)
                    )
                )
                if now >= self._expires_at(execution, chunks):
                    denial = ProblemException(
                        status=410,
                        code="LOG_EXPIRED",
                        title="日志正文已到期",
                        detail="执行摘要仍保留，但脱敏日志正文已按保留策略删除。",
                    )
                elif (
                    sum(chunk.byte_size for chunk in chunks if chunk.body_available)
                    > self.settings.log_export_limit_bytes
                ):
                    denial = ProblemException(
                        status=413,
                        code="LOG_EXPORT_TOO_LARGE",
                        title="日志下载超过单次上限",
                        detail="请使用分页日志查看本次执行。",
                    )
                else:
                    bodies: list[bytes] = []
                    versions: set[str] = set()
                    for chunk in chunks:
                        if not chunk.body_available:
                            continue
                        try:
                            bodies.append(self._load_indexed_body(chunk))
                            versions.add(chunk.redaction_rules_version)
                        except _BodyProblem as exc:
                            self._mark_chunk_unavailable(
                                session,
                                execution=execution,
                                chunk=chunk,
                                now=now,
                                reason=exc.reason,
                            )
                    gaps = list(
                        session.scalars(
                            select(ExecutionLogGap)
                            .where(ExecutionLogGap.execution_id == execution.id)
                            .order_by(
                                ExecutionLogGap.detected_at,
                                ExecutionLogGap.gap_no,
                                ExecutionLogGap.id,
                            )
                        )
                    )
                    content = b"".join(bodies)
                    result = LogDownload(
                        content=content,
                        content_sha256=hashlib.sha256(content).hexdigest(),
                        redaction_rules_version=(
                            next(iter(versions)) if len(versions) == 1 else "1.0"
                        ),
                        truncated=execution.log_truncated,
                        incomplete=execution.log_incomplete,
                        raw_received_bytes=(execution.log_raw_received_bytes),
                        redacted_received_bytes=(execution.log_redacted_received_bytes),
                        stored_bytes=len(content),
                        dropped_bytes=execution.log_dropped_bytes,
                        gap_count=len(gaps),
                        truncation_reason=_truncation_reason(gaps),
                    )
        except ProblemException:
            raise
        except BaseException as exc:
            self._audit_export(
                principal=principal,
                execution_id=execution_id,
                audit=audit,
                outcome="FAILED",
                reason_code="LOG_EXPORT_FAILED",
                metadata={},
            )
            raise ProblemException(
                status=500,
                code="LOG_EXPORT_FAILED",
                title="日志下载失败",
                detail="服务未返回任何未审计或未验证的日志内容。",
            ) from exc

        if denial is not None:
            self._audit_export(
                principal=principal,
                execution_id=execution_id,
                audit=audit,
                outcome="DENIED",
                reason_code=denial.code,
                metadata={},
            )
            raise denial
        if result is None:
            raise RuntimeError("log export did not produce a result")
        self._audit_export(
            principal=principal,
            execution_id=execution_id,
            audit=audit,
            outcome="SUCCEEDED",
            reason_code=None,
            metadata={
                "content_sha256": result.content_sha256,
                "stored_bytes": str(result.stored_bytes),
                "truncated": result.truncated,
                "incomplete": result.incomplete,
                "gap_count": str(result.gap_count),
            },
        )
        return result

    def _load_worker_redacted_body(
        self,
        path: Path,
        *,
        execution_id: UUID,
        attempt_id: UUID,
        expected_size: int,
    ) -> _StoredBody:
        resolved, storage_key = self._validated_path(
            path,
            execution_id=execution_id,
            attempt_id=attempt_id,
        )
        body = self._read_regular_file(resolved)
        if len(body) != expected_size:
            raise _BodyProblem("STORAGE_FAILURE")
        try:
            body.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise _BodyProblem("DECODE_ERROR") from exc
        return _StoredBody(
            body=body,
            storage_key=storage_key,
            sha256=hashlib.sha256(body).hexdigest(),
        )

    def _load_indexed_body(self, chunk: ExecutionLogChunk) -> bytes:
        path = self._path_for_storage_key(chunk.storage_key)
        body = self._read_regular_file(path)
        if len(body) != chunk.byte_size or not hmac.compare_digest(
            hashlib.sha256(body).hexdigest(),
            chunk.sha256,
        ):
            raise _BodyProblem("STORAGE_FAILURE")
        try:
            body.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise _BodyProblem("DECODE_ERROR") from exc
        return body

    def _validated_path(
        self,
        path: Path,
        *,
        execution_id: UUID,
        attempt_id: UUID,
    ) -> tuple[Path, str]:
        root = self.settings.log_volume_path
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if root.is_symlink():
            raise _BodyProblem("STORAGE_FAILURE")
        try:
            resolved_root = root.resolve(strict=True)
            resolved = path.resolve(strict=True)
            relative = resolved.relative_to(resolved_root)
        except (OSError, ValueError) as exc:
            raise _BodyProblem("STORAGE_FAILURE") from exc
        expected = Path(str(execution_id)) / f"{attempt_id}.log"
        if (
            relative != expected
            or path.is_symlink()
            or any(
                candidate.is_symlink()
                for candidate in _path_chain(
                    resolved_root,
                    resolved.parent,
                )
            )
        ):
            raise _BodyProblem("STORAGE_FAILURE")
        return resolved, relative.as_posix()

    def _path_for_storage_key(self, storage_key: str) -> Path:
        key = PurePosixPath(storage_key)
        if (
            key.is_absolute()
            or not key.parts
            or any(part in {"", ".", ".."} or "\\" in part for part in key.parts)
        ):
            raise _BodyProblem("STORAGE_FAILURE")
        root = self.settings.log_volume_path
        if root.is_symlink():
            raise _BodyProblem("STORAGE_FAILURE")
        try:
            resolved_root = root.resolve(strict=True)
            raw_candidate = resolved_root / Path(*key.parts)
            if raw_candidate.is_symlink() or any(
                part.is_symlink() for part in _path_chain(resolved_root, raw_candidate.parent)
            ):
                raise _BodyProblem("STORAGE_FAILURE")
            candidate = raw_candidate.resolve(strict=True)
            candidate.relative_to(resolved_root)
        except (OSError, ValueError) as exc:
            raise _BodyProblem("STORAGE_FAILURE") from exc
        return candidate

    @staticmethod
    def _read_regular_file(path: Path) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise _BodyProblem("STORAGE_FAILURE") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise _BodyProblem("STORAGE_FAILURE")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                return handle.read()
        finally:
            os.close(descriptor)

    def _discard_safe_log_path(
        self,
        path: Path,
        *,
        execution_id: UUID,
        attempt_id: UUID,
    ) -> None:
        try:
            resolved, _ = self._validated_path(
                path,
                execution_id=execution_id,
                attempt_id=attempt_id,
            )
        except _BodyProblem:
            return
        try:
            resolved.unlink(missing_ok=True)
        except OSError:
            return

    def _append_gaps(
        self,
        session: Session,
        *,
        execution_id: UUID,
        attempt_id: UUID,
        first_sequence: int,
        gaps: list[tuple[str, int, int, int, int]],
        detected_at: datetime,
    ) -> None:
        next_gap = (
            session.scalar(
                select(func.max(ExecutionLogGap.gap_no)).where(
                    ExecutionLogGap.execution_id == execution_id,
                    ExecutionLogGap.attempt_id == attempt_id,
                )
            )
            or 0
        ) + 1
        for offset, (
            reason,
            raw_received,
            redacted_received,
            stored,
            dropped,
        ) in enumerate(gaps):
            gap_no = next_gap + offset
            evidence: dict[str, object] = {
                "execution_id": str(execution_id),
                "attempt_id": str(attempt_id),
                "gap_no": gap_no,
                "reason": reason,
                "after_sequence": None,
                "before_sequence": None,
                "raw_received_bytes": raw_received,
                "redacted_received_bytes": redacted_received,
                "stored_bytes": stored,
                "dropped_bytes": dropped,
                "detected_at": _rfc3339(detected_at),
                "first_affected_sequence": first_sequence,
            }
            evidence_hash = _domain_hash("DXLOGGAPv1", evidence)
            _add_gap(
                session,
                execution_id=execution_id,
                attempt_id=attempt_id,
                gap_no=gap_no,
                reason=reason,
                raw_received_bytes=raw_received,
                redacted_received_bytes=redacted_received,
                stored_bytes=stored,
                dropped_bytes=dropped,
                detected_at=detected_at,
                evidence_hash=evidence_hash,
            )

    def _mark_chunk_unavailable(
        self,
        session: Session,
        *,
        execution: Execution,
        chunk: ExecutionLogChunk,
        now: datetime,
        reason: str,
    ) -> None:
        if not chunk.body_available:
            return
        chunk.body_available = False
        chunk.deleted_at = now
        execution.log_stored_bytes = max(
            0,
            execution.log_stored_bytes - chunk.stored_bytes,
        )
        execution.log_dropped_bytes = (
            execution.log_redacted_received_bytes - execution.log_stored_bytes
        )
        execution.log_incomplete = True
        execution.state_version += 1
        self._append_gaps(
            session,
            execution_id=execution.id,
            attempt_id=chunk.attempt_id,
            first_sequence=chunk.first_sequence,
            gaps=[
                (
                    reason,
                    0,
                    chunk.stored_bytes,
                    0,
                    chunk.stored_bytes,
                )
            ],
            detected_at=now,
        )
        try:
            self._path_for_storage_key(chunk.storage_key).unlink(missing_ok=True)
        except (OSError, _BodyProblem):
            return

    def _render_chunk(
        self,
        chunk: ExecutionLogChunk,
        body: bytes,
    ) -> list[LogLine]:
        sequence = chunk.first_sequence
        result: list[LogLine] = []
        for message, stored_bytes in _display_lines(body):
            result.append(
                LogLine(
                    sequence=sequence,
                    timestamp=ensure_aware(chunk.created_at),
                    stream="SYSTEM",
                    level=_infer_level(message),
                    message=message,
                    line_truncated=(
                        chunk.contains_truncated_line and sequence == chunk.first_sequence
                    ),
                    raw_received_bytes=stored_bytes,
                    redacted_received_bytes=stored_bytes,
                    stored_bytes=stored_bytes,
                    dropped_bytes=0,
                )
            )
            sequence += 1
        return result

    def _expires_at(
        self,
        execution: Execution,
        chunks: list[ExecutionLogChunk],
    ) -> datetime:
        if chunks:
            return min(ensure_aware(chunk.expires_at) for chunk in chunks)
        return ensure_aware(execution.created_at) + timedelta(days=self.settings.log_retention_days)

    def _encode_cursor(
        self,
        *,
        actor_id: UUID,
        execution_id: UUID,
        next_sequence: int,
        stream: str | None,
    ) -> str:
        payload = {
            "v": 1,
            "actor_id": str(actor_id),
            "execution_id": str(execution_id),
            "next_sequence": next_sequence,
            "stream": stream,
        }
        body = rfc8785.dumps(payload)
        signature = hmac.new(
            self.control._integrity_hmac_key,  # noqa: SLF001
            _CURSOR_DOMAIN + body,
            hashlib.sha256,
        ).digest()
        return base64.urlsafe_b64encode(body + signature).rstrip(b"=").decode("ascii")

    def _decode_cursor(
        self,
        cursor: str,
        *,
        actor_id: UUID,
        execution_id: UUID,
        stream: str | None,
    ) -> int:
        try:
            padding = "=" * (-len(cursor) % 4)
            decoded = base64.urlsafe_b64decode(cursor + padding)
            if len(decoded) <= 32:
                raise ValueError
            canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
            if not hmac.compare_digest(cursor, canonical):
                raise ValueError
            body, signature = decoded[:-32], decoded[-32:]
            expected = hmac.new(
                self.control._integrity_hmac_key,  # noqa: SLF001
                _CURSOR_DOMAIN + body,
                hashlib.sha256,
            ).digest()
            payload = json.loads(body)
            next_sequence = int(payload["next_sequence"])
            if (
                not hmac.compare_digest(signature, expected)
                or payload.get("v") != 1
                or payload.get("actor_id") != str(actor_id)
                or payload.get("execution_id") != str(execution_id)
                or payload.get("stream") != stream
                or next_sequence < 1
            ):
                raise ValueError
            return next_sequence
        except (
            ValueError,
            KeyError,
            TypeError,
            json.JSONDecodeError,
        ):
            raise ProblemException(
                status=400,
                code="CURSOR_INVALID",
                title="日志游标无效",
                detail="请从第一页重新加载日志。",
            ) from None

    @staticmethod
    def _gap_response(gap: ExecutionLogGap) -> LogGap:
        return LogGap(
            gap_no=gap.gap_no,
            reason=gap.reason,
            after_sequence=gap.after_sequence,
            before_sequence=gap.before_sequence,
            raw_received_bytes=gap.raw_received_bytes,
            redacted_received_bytes=gap.redacted_received_bytes,
            stored_bytes=gap.stored_bytes,
            dropped_bytes=gap.dropped_bytes,
            detected_at=ensure_aware(gap.detected_at),
            evidence_hash=gap.evidence_hash,
        )

    def _audit_export(
        self,
        *,
        principal: Principal,
        execution_id: UUID,
        audit: AuditContext,
        outcome: str,
        reason_code: str | None,
        metadata: dict[str, object],
    ) -> None:
        with self.control.sessions.begin() as session:
            execution = session.get(Execution, execution_id)
            organization = session.get(
                Organization,
                principal.organization_id,
            )
            actor = session.get(User, principal.user_id)
            if execution is None or organization is None or actor is None:
                raise RuntimeError("log export audit identity is missing")
            session.execute(
                select(Organization.id).where(Organization.id == organization.id).with_for_update()
            ).scalar_one()
            previous = session.scalar(
                select(AuditEvent)
                .where(AuditEvent.organization_id == organization.id)
                .order_by(AuditEvent.organization_sequence.desc())
                .limit(1)
            )
            sequence = previous.organization_sequence + 1 if previous else 1
            previous_hash = previous.event_hash if previous else None
            occurred_at = utc_now()
            event_id = uuid4()
            event: dict[str, object] = {
                "schema_version": "1.0",
                "event_id": str(event_id),
                "organization_id": str(organization.id),
                "sequence": sequence,
                "project_id": str(execution.project_id),
                "occurred_at": _rfc3339(occurred_at),
                "action": "EXECUTION_LOG_EXPORTED",
                "actor": {
                    "kind": "USER",
                    "user_id": str(actor.id),
                    "display_name": actor.display_name,
                },
                "target": {
                    "type": "EXECUTION",
                    "id": str(execution.id),
                    "name": None,
                },
                "request": {
                    "request_id": str(audit.request_id),
                    "source_ip": (audit.source_ip[:45] if audit.source_ip else None),
                    "user_agent": self.control._safe_audit_user_agent(  # noqa: SLF001
                        audit.user_agent
                    ),
                },
                "outcome": outcome,
                "reason_code": reason_code,
                "changes": {
                    "before_hash": None,
                    "after_hash": None,
                    "changed_fields": [],
                },
                "metadata": metadata,
                "integrity": {
                    "algorithm": "SHA-256",
                    "canonicalization": "RFC8785",
                    "chain_scope": "ORGANIZATION_SEQUENCE",
                    "previous_hash": previous_hash,
                },
            }
            prefix = (
                "DXAUDITv1\n"
                f"{str(organization.id).lower()}\n"
                f"{sequence}\n"
                f"{previous_hash or ('0' * 64)}\n"
            ).encode()
            event_hash = hashlib.sha256(prefix + rfc8785.dumps(event)).hexdigest()
            integrity = event["integrity"]
            if not isinstance(integrity, dict):
                raise RuntimeError("audit integrity shape is invalid")
            integrity["event_hash"] = event_hash
            advance_audit_chain_watermark(
                session,
                organization_id=organization.id,
                previous_sequence=sequence - 1,
                previous_hash=previous_hash,
                sequence=sequence,
                event_hash=event_hash,
                updated_at=occurred_at,
            )
            session.add(
                AuditEvent(
                    id=event_id,
                    organization_id=organization.id,
                    organization_sequence=sequence,
                    project_id=execution.project_id,
                    event_json=event,
                    canonicalization_version="RFC8785-v1",
                    previous_hash=previous_hash,
                    event_hash=event_hash,
                    occurred_at=occurred_at,
                    expires_at=occurred_at + timedelta(days=730),
                )
            )

    @staticmethod
    def _validate_process_accounting(result: ProcessLogResult) -> None:
        values = (
            result.raw_received_bytes,
            result.redacted_received_bytes,
            result.stored_bytes,
            result.dropped_bytes,
        )
        if any(value < 0 for value in values):
            raise ValueError("log byte counters must be nonnegative")
        if result.dropped_bytes != result.redacted_received_bytes - result.stored_bytes:
            raise ValueError("process log byte accounting is invalid")
        if sum(gap.dropped_bytes for gap in result.gaps) != result.dropped_bytes:
            raise ValueError("process log gaps do not account for dropped bytes")

    @staticmethod
    def _expired() -> None:
        raise ProblemException(
            status=410,
            code="LOG_EXPIRED",
            title="日志正文已到期",
            detail="执行摘要仍保留，但脱敏日志正文已按保留策略删除。",
        )


def _display_line_count(body: bytes) -> int:
    return sum(1 for _message, _stored in _display_lines(body))


def append_reconciler_fence_gap(
    session: Session,
    *,
    execution: Execution,
    attempt_id: UUID,
    detected_at: datetime,
) -> None:
    existing = session.scalar(
        select(ExecutionLogGap.id).where(
            ExecutionLogGap.execution_id == execution.id,
            ExecutionLogGap.attempt_id == attempt_id,
            ExecutionLogGap.reason == "FENCE_LOST",
        )
    )
    if existing is not None:
        execution.log_incomplete = True
        return
    gap_no = (
        session.scalar(
            select(func.max(ExecutionLogGap.gap_no)).where(
                ExecutionLogGap.execution_id == execution.id,
                ExecutionLogGap.attempt_id == attempt_id,
            )
        )
        or 0
    ) + 1
    first_sequence = (
        session.scalar(
            select(func.max(ExecutionLogChunk.last_sequence)).where(
                ExecutionLogChunk.execution_id == execution.id
            )
        )
        or 0
    ) + 1
    evidence: dict[str, object] = {
        "execution_id": str(execution.id),
        "attempt_id": str(attempt_id),
        "gap_no": gap_no,
        "reason": "FENCE_LOST",
        "after_sequence": None,
        "before_sequence": None,
        "raw_received_bytes": 0,
        "redacted_received_bytes": 0,
        "stored_bytes": 0,
        "dropped_bytes": 0,
        "detected_at": _rfc3339(detected_at),
        "first_affected_sequence": first_sequence,
    }
    _add_gap(
        session,
        execution_id=execution.id,
        attempt_id=attempt_id,
        gap_no=gap_no,
        reason="FENCE_LOST",
        raw_received_bytes=0,
        redacted_received_bytes=0,
        stored_bytes=0,
        dropped_bytes=0,
        detected_at=detected_at,
        evidence_hash=_domain_hash("DXLOGGAPv1", evidence),
    )
    execution.log_incomplete = True


def _add_gap(
    session: Session,
    *,
    execution_id: UUID,
    attempt_id: UUID,
    gap_no: int,
    reason: str,
    raw_received_bytes: int,
    redacted_received_bytes: int,
    stored_bytes: int,
    dropped_bytes: int,
    detected_at: datetime,
    evidence_hash: str,
) -> None:
    session.add(
        ExecutionLogGap(
            id=uuid4(),
            execution_id=execution_id,
            attempt_id=attempt_id,
            gap_no=gap_no,
            reason=reason,
            after_sequence=None,
            before_sequence=None,
            raw_received_bytes=raw_received_bytes,
            redacted_received_bytes=redacted_received_bytes,
            stored_bytes=stored_bytes,
            dropped_bytes=dropped_bytes,
            detected_at=detected_at,
            evidence_hash=evidence_hash,
        )
    )


def _display_lines(body: bytes) -> list[tuple[str, int]]:
    result: list[tuple[str, int]] = []
    for line in body.splitlines(keepends=True):
        newline_length = 0
        if line.endswith(b"\r\n"):
            newline_length = 2
        elif line.endswith((b"\n", b"\r")):
            newline_length = 1
        content = line[:-newline_length] if newline_length else line
        text = content.decode("utf-8", errors="strict")
        pieces = [
            text[index : index + _MAX_MESSAGE_CHARACTERS]
            for index in range(0, len(text), _MAX_MESSAGE_CHARACTERS)
        ] or [""]
        for index, piece in enumerate(pieces):
            stored = len(piece.encode("utf-8"))
            if index == len(pieces) - 1:
                stored += newline_length
            result.append((piece, stored))
    return result


def _infer_level(message: str) -> str:
    match = _LEVEL_PATTERN.search(message[:256])
    if match is None:
        return "UNKNOWN"
    value = match.group(1).upper()
    if value == "WARNING":
        return "WARN"
    if value in {"SEVERE", "FATAL"}:
        return "ERROR"
    return value


def _truncation_reason(gaps: list[ExecutionLogGap]) -> str:
    reasons = {gap.reason for gap in gaps}
    for reason in ("EXECUTION_LIMIT", "LINE_LIMIT", "RING_EVICTION"):
        if reason in reasons:
            return reason
    return "NONE"


def _path_chain(root: Path, leaf: Path) -> list[Path]:
    relative = leaf.relative_to(root)
    result: list[Path] = []
    current = root
    for part in relative.parts:
        current = current / part
        result.append(current)
    return result


def _domain_hash(domain: str, value: object) -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\n" + rfc8785.dumps(value)).hexdigest()


def _rfc3339(value: datetime) -> str:
    return (
        ensure_aware(value)
        .astimezone(UTC)
        .isoformat()
        .replace(
            "+00:00",
            "Z",
        )
    )
