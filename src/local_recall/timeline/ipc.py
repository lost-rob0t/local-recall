"""Authenticated IPC request handler for timeline inspection and deletion."""

from __future__ import annotations

import asyncio
import base64
import json
import threading
from uuid import UUID

from local_recall.audit.errors import AuditFailure
from local_recall.audit.recorder import AuditRecorder
from local_recall.cli_contract import (
    MAX_QUERY_RESULT_TEXT_LENGTH,
    CliCommand,
    CliDeletionPayload,
    CliOutcome,
    CliQueryPayload,
    CliRequest,
    CliResponse,
)
from local_recall.timeline.activity_rebuild import TimelineRebuildFailure
from local_recall.timeline.deletion import DeletionCoordinator
from local_recall.timeline.inspection import PreviewUnavailable, TimelineInspector, TimelineQuery
from local_recall.timeline.scope import DeletionScope, DeletionScopeResolver, ScopeResolutionFailure


class TimelineDeletionHandler:
    """Serve owner inspection and destructive requests over authenticated IPC.

    The handler is the only daemon-side authority for the issue #30 surface:
    it maps closed typed CLI commands onto the timeline inspector, the bounded
    deletion-scope resolver, and the crash-recoverable deletion coordinator.
    All failure reasons are fixed and content-free.
    """

    def __init__(
        self,
        *,
        inspector: TimelineInspector,
        resolver: DeletionScopeResolver,
        coordinator: DeletionCoordinator,
        audit: AuditRecorder,
    ) -> None:
        self._inspector = inspector
        self._resolver = resolver
        self._coordinator = coordinator
        self._audit = audit
        self._serial = threading.Lock()

    def __repr__(self) -> str:
        return "TimelineDeletionHandler(dependencies=redacted)"

    def __call__(self, request: CliRequest) -> CliResponse:
        with self._serial:
            return asyncio.run(self._handle(request))

    async def _handle(self, request: CliRequest) -> CliResponse:
        if request.command is CliCommand.TIMELINE:
            return await self._timeline(request)
        if request.command is CliCommand.PREVIEW_RECORD:
            return await self._preview(request)
        if request.command is CliCommand.DELETE_RECORDS:
            return await self._delete(request)
        return _failure(request, CliOutcome.INVALID, "unsupported-command")

    async def _timeline(self, request: CliRequest) -> CliResponse:
        if request.start is None or request.end is None:
            return _failure(request, CliOutcome.INVALID, "timeline-requires-bounds")
        page = await self._inspector.timeline(_timeline_query(request))
        text = json.dumps(
            [
                {
                    "application": entry.application,
                    "captured_at": entry.captured_at.isoformat(),
                    "cluster_id": entry.cluster_id,
                    "policy_revision": entry.policy_revision,
                    "record_id": str(entry.record_id),
                    "redaction_finding_count": entry.redaction_finding_count,
                    "workspace": entry.workspace,
                }
                for entry in page.entries
            ],
            sort_keys=True,
            separators=(",", ":"),
        )
        return _query_response(request, text)

    async def _preview(self, request: CliRequest) -> CliResponse:
        record_id = UUID(hex=request.record_ids[0])
        try:
            if request.target == "text":
                preview = await self._inspector.preview_text(record_id)
                payload = json.dumps(
                    {
                        "captured_at": preview.captured_at.isoformat(),
                        "policy_revision": preview.policy_revision,
                        "record_id": str(preview.record_id),
                        "text": preview.text,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            else:
                image = await self._inspector.preview_screenshot(record_id)
                payload = json.dumps(
                    {
                        "captured_at": image.captured_at.isoformat(),
                        "height": image.height,
                        "pixel_format": image.pixel_format.value,
                        "pixels": base64.b64encode(image.pixels).decode("ascii"),
                        "policy_revision": image.policy_revision,
                        "record_id": str(image.record_id),
                        "stride": image.stride,
                        "width": image.width,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
        except PreviewUnavailable:
            return _failure(request, CliOutcome.INVALID, "preview-unavailable")
        return _query_response(request, payload)

    async def _delete(self, request: CliRequest) -> CliResponse:
        try:
            scope = _deletion_scope(request)
        except ValueError, ScopeResolutionFailure:
            return _failure(request, CliOutcome.INVALID, "deletion-scope-invalid")
        try:
            resolved = await self._resolver.resolve(scope)
            result = await self._coordinator.delete(
                request_id=request.request_id,
                record_ids=resolved,
            )
        except ScopeResolutionFailure, ValueError:
            self._audit_deletion(request, scope, 0, succeeded=False)
            return _failure(request, CliOutcome.INVALID, "deletion-scope-invalid")
        except TimelineRebuildFailure, RuntimeError:
            self._audit_deletion(request, scope, 0, succeeded=False)
            return _failure(request, CliOutcome.FAULTED, "deletion-failed")
        try:
            self._audit_deletion(request, scope, result.deleted_count, succeeded=True)
        except AuditFailure:
            return _failure(request, CliOutcome.INTERNAL_FAILURE, "audit-failed")
        return CliResponse.success(
            request_id=request.request_id,
            deletion_payload=CliDeletionPayload(
                deleted_count=result.deleted_count,
                scope_kind=scope.kind.value,
                recovered=result.recovered,
            ),
        )

    def _audit_deletion(
        self,
        request: CliRequest,
        scope: DeletionScope,
        count: int,
        *,
        succeeded: bool,
    ) -> None:
        self._audit.deletion_request(
            scope_kind=scope.kind.value,
            count=count,
            succeeded=succeeded,
            correlation_id=UUID(hex=request.request_id),
        )


def _timeline_query(request: CliRequest) -> TimelineQuery:
    if request.start is None or request.end is None:
        raise ValueError("timeline query bounds are required")
    return TimelineQuery(
        start_at=request.start,
        end_at=request.end,
        application=request.application,
    )


def _deletion_scope(request: CliRequest) -> DeletionScope:
    if request.record_ids:
        return DeletionScope.for_records(tuple(UUID(hex=item) for item in request.record_ids))
    if request.cluster_id is not None:
        return DeletionScope.for_cluster(request.cluster_id)
    if request.application is not None:
        if request.start is None or request.end is None:
            raise ScopeResolutionFailure("application deletion requires explicit bounds")
        return DeletionScope.for_application(
            request.application,
            start_at=request.start,
            end_at=request.end,
        )
    if request.start is not None and request.end is not None:
        return DeletionScope.for_time_range(start_at=request.start, end_at=request.end)
    raise ScopeResolutionFailure("deletion scope is incomplete")


def _query_response(request: CliRequest, text: str) -> CliResponse:
    if len(text) > MAX_QUERY_RESULT_TEXT_LENGTH:
        return _failure(request, CliOutcome.INVALID, "result-too-large")
    return CliResponse.success(
        request_id=request.request_id,
        query_payload=CliQueryPayload(text=text),
    )


def _failure(request: CliRequest, outcome: CliOutcome, reason_code: str) -> CliResponse:
    return CliResponse.failure(
        request_id=request.request_id,
        outcome=outcome,
        reason_code=reason_code,
    )
