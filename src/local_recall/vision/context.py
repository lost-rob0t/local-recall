"""Policy-gated visual context explanation for the Zara companion client."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol

from local_recall.audit.models import AuditEvent
from local_recall.audit.recorder import AuditRecorder
from local_recall.domain.frames import RedactedRecord
from local_recall.domain.lifecycle import CaptureState, CaptureStateSnapshot
from local_recall.retrieval.service import RetrievalPolicyDecision
from local_recall.vision.service import (
    VisionAnalysis,
    VisionRefused,
    VisionUnavailable,
)

PROTOCOL_VERSION = "zara-visual-context-v1"
_MAX_RECORDS = 8
_MAX_ANSWER_CHARS = 4000
_MAX_REQUEST_ID_CHARS = 128
_CURRENT_WINDOW = timedelta(minutes=10)
_RECENT_WINDOW = timedelta(hours=24)


class VisualContextSelector(StrEnum):
    CURRENT = "current"
    RECENT = "recent"
    BOUNDED_WINDOW = "bounded_window"


class RemoteAuthorizationMode(StrEnum):
    ABSENT = "absent"
    EXPLICIT = "explicit"


class VisualContextOutcome(StrEnum):
    EXPLAINED = "explained"
    DENIED = "denied"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True, repr=False)
class ExplainVisualContextRequest:
    """Versioned typed request; the client owns only these fields."""

    protocol_version: str
    request_id: str
    selector: VisualContextSelector
    deadline: datetime
    start: datetime | None = None
    end: datetime | None = None
    maximum_records: int = 3
    remote_authorization: RemoteAuthorizationMode = RemoteAuthorizationMode.ABSENT

    def __post_init__(self) -> None:
        if self.protocol_version != PROTOCOL_VERSION:
            raise ValueError("unsupported visual-context protocol version")
        if not self.request_id or len(self.request_id) > _MAX_REQUEST_ID_CHARS:
            raise ValueError("visual-context request id is invalid")
        if any(character in self.request_id for character in ("/", "\\", "\x00", " ")):
            raise ValueError("visual-context request id is invalid")
        if self.deadline.tzinfo is None or self.deadline.utcoffset() is None:
            raise ValueError("visual-context deadline must be timezone-aware")
        if self.maximum_records < 1 or self.maximum_records > _MAX_RECORDS:
            raise ValueError(f"maximum_records must be between 1 and {_MAX_RECORDS}")
        if self.selector is VisualContextSelector.BOUNDED_WINDOW:
            if self.start is None or self.end is None:
                raise ValueError("bounded_window requires start and end")
            if self.start >= self.end:
                raise ValueError("bounded_window start must precede end")
        elif self.start is not None or self.end is not None:
            raise ValueError("current/recent selectors reject explicit bounds")

    def __repr__(self) -> str:
        return "ExplainVisualContextRequest(request_id=<opaque>, content=redacted)"


@dataclass(frozen=True, slots=True, repr=False)
class ExplainVisualContextResponse:
    """Closed sanitized response: bounded text plus opaque indicators only."""

    request_id: str
    outcome: VisualContextOutcome
    explanation: str | None = None
    selected_start: datetime | None = None
    selected_end: datetime | None = None
    record_count: int = 0
    provider_class: str | None = None
    confidence_summary: float | None = None
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if self.provider_class is not None and self.provider_class not in (
            "local",
            "authorized_remote",
        ):
            raise ValueError("provider_class is invalid")
        if self.outcome is VisualContextOutcome.EXPLAINED:
            if not self.explanation or len(self.explanation) > _MAX_ANSWER_CHARS:
                raise ValueError("explained responses require bounded text")
            if (
                self.provider_class is None
                or self.selected_start is None
                or (self.selected_end is None)
            ):
                raise ValueError("explained responses require provider and time range")
        else:
            if self.explanation is not None:
                raise ValueError("denied/unavailable responses cannot carry text")
            if not self.reason_code:
                raise ValueError("denied/unavailable responses require a reason code")

    def to_dict(self) -> dict[str, object]:
        return {
            "protocol_version": PROTOCOL_VERSION,
            "request_id": self.request_id,
            "outcome": self.outcome.value,
            "explanation": self.explanation,
            "selected_start": self.selected_start.isoformat() if self.selected_start else None,
            "selected_end": self.selected_end.isoformat() if self.selected_end else None,
            "record_count": self.record_count,
            "provider_class": self.provider_class,
            "confidence_summary": self.confidence_summary,
            "reason_code": self.reason_code,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    def __repr__(self) -> str:
        return (
            f"ExplainVisualContextResponse(request_id={self.request_id!r}, "
            f"outcome={self.outcome.value!r}, record_count={self.record_count}, "
            "content=redacted)"
        )


class LifecyclePort(Protocol):
    def observe(self) -> CaptureStateSnapshot: ...

    def session_locked(self) -> bool: ...


class QueryPolicyPort(Protocol):
    async def authorize_query(self, query: VisualContextSelector) -> RetrievalPolicyDecision: ...


class WorkingSetPort(Protocol):
    async def select(
        self,
        selector: VisualContextSelector,
        start: datetime | None,
        end: datetime | None,
        limit: int,
    ) -> tuple[RedactedRecord, ...]: ...


class VisionPort(Protocol):
    async def enrich(
        self, record: RedactedRecord, *, egress_authorization: object = None
    ) -> VisionAnalysis: ...


class VisualContextService:
    """Explain current/recent desktop context without ever exporting artifacts."""

    def __init__(
        self,
        *,
        lifecycle: LifecyclePort,
        policy: QueryPolicyPort,
        working_set: WorkingSetPort,
        vision: VisionPort,
        audit: AuditRecorder,
        now: Callable[[], datetime],
        egress_gate: object = None,
    ) -> None:
        del egress_gate
        self._lifecycle = lifecycle
        self._policy = policy
        self._working_set = working_set
        self._vision = vision
        self._audit = audit
        self._now = now
        self._cancelled: set[str] = set()

    def cancel(self, request_id: str) -> None:
        self._cancelled.add(request_id)

    async def explain(
        self,
        request: ExplainVisualContextRequest,
        *,
        egress_authorization: object = None,
        debug: bool = False,
    ) -> ExplainVisualContextResponse:
        del debug
        rejection = self._preflight(request)
        if rejection is not None:
            self._audit_outcome(request.request_id, rejected=True)
            return self._denied(request.request_id, rejection)
        self._audit.record_visual_context_acceptance()
        start, end = self._window(request)
        try:
            policy_decision = await self._policy.authorize_query(request.selector)
        except Exception:
            self._audit_outcome(request.request_id, rejected=True)
            return self._denied(request.request_id, "query-policy-denied")
        if not policy_decision.allowed:
            self._audit_outcome(request.request_id, rejected=True)
            return self._denied(request.request_id, "query-policy-denied")
        if self._now() >= request.deadline:
            self._audit_outcome(request.request_id, rejected=True)
            return self._denied(request.request_id, "deadline-expired")
        if request.request_id in self._cancelled:
            self._audit_outcome(request.request_id, rejected=True)
            return self._denied(request.request_id, "cancelled")
        try:
            records = await self._working_set.select(
                request.selector,
                start,
                end,
                request.maximum_records,
            )
        except Exception:
            self._audit_outcome(request.request_id, rejected=True)
            return self._unavailable(request.request_id, "working-set-unavailable")
        if not records:
            self._audit_outcome(request.request_id, rejected=True)
            return self._denied(request.request_id, "missing-context")
        remote_requested = request.remote_authorization is RemoteAuthorizationMode.EXPLICIT
        if remote_requested and egress_authorization is None:
            self._audit_outcome(request.request_id, rejected=True)
            return self._denied(request.request_id, "remote-not-authorized")
        try:
            analyses: list[VisionAnalysis] = []
            for record in records:
                analysis = await self._vision.enrich(
                    record, egress_authorization=egress_authorization
                )
                analyses.append(analysis)
        except VisionRefused:
            self._audit_outcome(request.request_id, rejected=True)
            return self._denied(request.request_id, "remote-not-authorized")
        except VisionUnavailable:
            self._audit_outcome(request.request_id, rejected=True)
            return self._unavailable(request.request_id, "vision-unavailable")
        except Exception:
            self._audit_outcome(request.request_id, rejected=True)
            return self._unavailable(request.request_id, "vision-failed")
        if self._now() >= request.deadline:
            self._audit_outcome(request.request_id, rejected=True)
            return self._denied(request.request_id, "deadline-expired")
        self._audit_outcome(request.request_id, rejected=False)
        return ExplainVisualContextResponse(
            request_id=request.request_id,
            outcome=VisualContextOutcome.EXPLAINED,
            explanation=_compose_explanation(analyses),
            selected_start=min(record.frame.captured_at for record in records),
            selected_end=max(record.frame.captured_at for record in records),
            record_count=len(records),
            provider_class="authorized_remote" if remote_requested else "local",
            confidence_summary=_confidence_summary(analyses),
        )

    def _preflight(self, request: ExplainVisualContextRequest) -> str | None:
        if self._now() >= request.deadline:
            return "deadline-expired"
        if request.request_id in self._cancelled:
            return "cancelled"
        snapshot: CaptureStateSnapshot = self._lifecycle.observe()
        if snapshot.privacy_mode or snapshot.state is CaptureState.PRIVACY:
            return "privacy-mode"
        if self._lifecycle.session_locked():
            return "session-locked"
        if snapshot.state not in (CaptureState.RECORDING, CaptureState.PAUSED):
            return "capture-not-active"
        if not snapshot.critical_dependencies_healthy:
            return "lifecycle-unhealthy"
        return None

    def _window(
        self, request: ExplainVisualContextRequest
    ) -> tuple[datetime | None, datetime | None]:
        now = self._now()
        if request.selector is VisualContextSelector.CURRENT:
            return (now - _CURRENT_WINDOW, now)
        if request.selector is VisualContextSelector.RECENT:
            return (now - _RECENT_WINDOW, now)
        return (request.start, request.end)

    def _denied(self, request_id: str, reason_code: str) -> ExplainVisualContextResponse:
        return ExplainVisualContextResponse(
            request_id=request_id,
            outcome=VisualContextOutcome.DENIED,
            reason_code=reason_code,
        )

    def _unavailable(self, request_id: str, reason_code: str) -> ExplainVisualContextResponse:
        return ExplainVisualContextResponse(
            request_id=request_id,
            outcome=VisualContextOutcome.UNAVAILABLE,
            reason_code=reason_code,
        )

    def _audit_outcome(self, request_id: str, *, rejected: bool) -> AuditEvent:
        del request_id
        return self._audit.record_visual_context_request(rejected=rejected)


def _compose_explanation(analyses: list[VisionAnalysis]) -> str:
    lines: list[str] = []
    for analysis in analyses:
        lines.append(f"{analysis.broad_task}: {analysis.visible_application_state}")
    text = "\n".join(lines)[:_MAX_ANSWER_CHARS]
    return text


def _confidence_summary(analyses: list[VisionAnalysis]) -> float | None:
    if not analyses:
        return None
    total = sum(1.0 - analysis.uncertainty for analysis in analyses)
    return round(total / len(analyses), 4)
