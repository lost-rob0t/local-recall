"""Typed timeline inspection with decrypt-on-demand previews."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID

from local_recall.activity.store import EncryptedActivityStore
from local_recall.domain._validation import require_aware
from local_recall.domain.frames import PixelFormat, RedactedRecord
from local_recall.domain.metadata import ContextMetadata
from local_recall.ports.encryption import DecryptionRequest, EncryptionProvider
from local_recall.ports.storage import CatalogRecord, DayRangeQuery, QueryableStorageBackend
from local_recall.timeline.scope import cluster_identifier

_MAX_LIMIT = 1_000
_DAY_QUERY_LIMIT = 10_000
_MAX_TIMELINE_SPAN_DAYS = 366
_MAX_PREVIEW_TEXT_CHARS = 16_384
_DAY = timedelta(days=1)


class PreviewUnavailable(RuntimeError):
    """Sanitized preview failure for a record that is not currently available."""


@dataclass(frozen=True, slots=True, repr=False)
class TimelineProvenance:
    field_name: str
    source_id: str
    observed_at: datetime
    confidence: float
    adapter_revision: str | None


@dataclass(frozen=True, slots=True, repr=False)
class TimelineEntry:
    record_id: UUID
    captured_at: datetime
    policy_revision: str
    redaction_finding_count: int
    application: str | None
    workspace: str | None
    cluster_id: str | None
    provenance: tuple[TimelineProvenance, ...]


@dataclass(frozen=True, slots=True, repr=False)
class TimelinePage:
    entries: tuple[TimelineEntry, ...]
    scanned: int
    truncated: bool


@dataclass(frozen=True, slots=True)
class TimelineQuery:
    start_at: datetime
    end_at: datetime
    application: str | None = field(default=None, repr=False)
    workspace: str | None = field(default=None, repr=False)
    limit: int = 100

    def __post_init__(self) -> None:
        require_aware(self.start_at, "start_at")
        require_aware(self.end_at, "end_at")
        if self.end_at <= self.start_at:
            raise ValueError("timeline query window is invalid")
        if self.end_at - self.start_at > _MAX_TIMELINE_SPAN_DAYS * _DAY:
            raise ValueError("timeline query window exceeds the span limit")
        if self.application is not None and not self.application:
            raise ValueError("timeline application filter must not be empty")
        if self.workspace is not None and not self.workspace:
            raise ValueError("timeline workspace filter must not be empty")
        if not 1 <= self.limit <= _MAX_LIMIT:
            raise ValueError("timeline query limit is invalid")


@dataclass(frozen=True, slots=True, repr=False)
class TimelineTextPreview:
    record_id: UUID
    captured_at: datetime
    policy_revision: str
    text: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class TimelineImagePreview:
    record_id: UUID
    captured_at: datetime
    policy_revision: str
    width: int
    height: int
    stride: int
    pixel_format: PixelFormat
    pixels: bytes


class TimelineInspector:
    """Owner-facing timeline listing and decrypt-on-demand previews.

    Listing exposes only user-requested redacted metadata, provenance, finding
    counts, policy revisions, and opaque cluster identifiers. Previews decrypt
    the exact requested record on demand and are never cached or persisted;
    decrypted content lives only in memory for the call lifetime.
    """

    def __init__(
        self,
        *,
        storage: QueryableStorageBackend,
        encryption: EncryptionProvider,
        activity_store: EncryptedActivityStore,
    ) -> None:
        self._storage = storage
        self._encryption = encryption
        self._activity_store = activity_store

    def __repr__(self) -> str:
        return "TimelineInspector(dependencies=redacted)"

    async def timeline(self, query: TimelineQuery) -> TimelinePage:
        cluster_by_record = await self._cluster_ids()
        start_day = query.start_at.astimezone(UTC).date()
        end_day = _inclusive_end_day(query.end_at)
        entries: list[TimelineEntry] = []
        scanned = 0
        truncated = False
        day = start_day
        while day <= end_day:
            candidates = await self._storage.list_candidates(
                DayRangeQuery(start_day=day, end_day=day, limit=_DAY_QUERY_LIMIT)
            )
            if len(candidates) >= _DAY_QUERY_LIMIT:
                break
            for candidate in candidates:
                record = await self._decrypt(candidate)
                if record is None:
                    continue
                if not _matches(query, record):
                    continue
                scanned += 1
                if scanned > query.limit:
                    truncated = True
                    continue
                entries.append(_entry(record, cluster_by_record))
            day = day + _DAY
        entries.sort(
            key=lambda item: (item.captured_at, str(item.record_id)),
            reverse=True,
        )
        return TimelinePage(entries=tuple(entries), scanned=scanned, truncated=truncated)

    async def preview_text(self, record_id: UUID) -> TimelineTextPreview:
        record = await self._load(record_id)
        text = "\n".join(record.frame.ocr_text)[:_MAX_PREVIEW_TEXT_CHARS]
        return TimelineTextPreview(
            record_id=record.record_id,
            captured_at=record.frame.captured_at,
            policy_revision=record.frame.policy_revision,
            text=text,
        )

    async def preview_screenshot(self, record_id: UUID) -> TimelineImagePreview:
        record = await self._load(record_id)
        return TimelineImagePreview(
            record_id=record.record_id,
            captured_at=record.frame.captured_at,
            policy_revision=record.frame.policy_revision,
            width=record.frame.width,
            height=record.frame.height,
            stride=record.frame.stride,
            pixel_format=record.frame.pixel_format,
            pixels=record.frame.pixels,
        )

    async def _load(self, record_id: UUID) -> RedactedRecord:
        envelope = await self._storage.get(record_id)
        if envelope is None:
            raise PreviewUnavailable("requested record is not available")
        record = await self._encryption.decrypt(DecryptionRequest(envelope, envelope.key))
        if record.record_id != record_id:
            raise PreviewUnavailable("requested record is not available")
        return record

    async def _decrypt(self, candidate: CatalogRecord) -> RedactedRecord | None:
        envelope = await self._storage.get(candidate.record.record_id)
        if envelope is None:
            return None
        record = await self._encryption.decrypt(DecryptionRequest(envelope, envelope.key))
        if record.record_id != candidate.record.record_id:
            raise PreviewUnavailable("timeline record identity mismatch")
        return record

    async def _cluster_ids(self) -> dict[UUID, str]:
        snapshot = await self._activity_store.load()
        if snapshot is None:
            return {}
        return {
            record_id: cluster_identifier(entry)
            for entry in snapshot.entries
            for record_id in entry.cluster.source_record_ids
        }


def _matches(query: TimelineQuery, record: RedactedRecord) -> bool:
    captured_at = record.frame.captured_at
    if not query.start_at <= captured_at < query.end_at:
        return False
    if query.application is not None:
        application = _string_field(record.frame.metadata, "application")
        if application is None or application.casefold() != query.application.casefold():
            return False
    if query.workspace is not None:
        workspace = _string_field(record.frame.metadata, "workspace")
        if workspace is None or workspace.casefold() != query.workspace.casefold():
            return False
    return True


def _entry(record: RedactedRecord, cluster_by_record: dict[UUID, str]) -> TimelineEntry:
    provenance = tuple(
        TimelineProvenance(
            field_name=context_field.name,
            source_id=item.source_id,
            observed_at=item.observed_at,
            confidence=item.confidence.value,
            adapter_revision=item.adapter_revision,
        )
        for context_field in record.frame.metadata.fields
        for item in context_field.provenance
    )
    return TimelineEntry(
        record_id=record.record_id,
        captured_at=record.frame.captured_at,
        policy_revision=record.frame.policy_revision,
        redaction_finding_count=len(record.frame.findings),
        application=_string_field(record.frame.metadata, "application"),
        workspace=_string_field(record.frame.metadata, "workspace"),
        cluster_id=cluster_by_record.get(record.record_id),
        provenance=provenance,
    )


def _string_field(metadata: ContextMetadata, name: str) -> str | None:
    value = metadata.get(name)
    return value if isinstance(value, str) else None


def _inclusive_end_day(end_at: datetime):
    return (end_at.astimezone(UTC) - timedelta(microseconds=1)).date()
