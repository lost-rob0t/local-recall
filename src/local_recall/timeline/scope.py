"""Closed typed deletion scopes and bounded scope resolution."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from enum import StrEnum
from uuid import UUID

from local_recall.activity.store import ActivityEntry, EncryptedActivityStore
from local_recall.domain._validation import require_aware
from local_recall.domain.frames import RedactedRecord
from local_recall.domain.metadata import ContextMetadata
from local_recall.ports.encryption import DecryptionRequest, EncryptionProvider
from local_recall.ports.storage import CatalogRecord, DayRangeQuery, QueryableStorageBackend

_MAX_SCOPE_RECORDS = 10_000
_DAY_QUERY_LIMIT = 10_000
_MAX_SCOPE_SPAN_DAYS = 366
_MAX_APPLICATION_LENGTH = 256
_CLUSTER_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_DAY = timedelta(days=1)


class DeletionScopeKind(StrEnum):
    RECORD_IDS = "record-ids"
    ACTIVITY_CLUSTER = "activity-cluster"
    APPLICATION = "application"
    TIME_RANGE = "time-range"


class ScopeResolutionFailure(RuntimeError):
    """Sanitized deletion-scope resolution failure."""


@dataclass(frozen=True, slots=True, repr=False)
class DeletionScope:
    """One closed destructive scope; exactly one selection kind per request."""

    kind: DeletionScopeKind
    record_ids: tuple[UUID, ...] = ()
    cluster_id: str | None = None
    application: str | None = field(default=None, repr=False)
    start_at: datetime | None = None
    end_at: datetime | None = None

    @classmethod
    def for_records(cls, record_ids: tuple[UUID, ...]) -> DeletionScope:
        _validate_record_ids(record_ids)
        return cls(kind=DeletionScopeKind.RECORD_IDS, record_ids=record_ids)

    @classmethod
    def for_cluster(cls, cluster_id: str) -> DeletionScope:
        if not _CLUSTER_ID_PATTERN.fullmatch(cluster_id):
            raise ValueError("deletion scope cluster identifier is invalid")
        return cls(kind=DeletionScopeKind.ACTIVITY_CLUSTER, cluster_id=cluster_id)

    @classmethod
    def for_application(
        cls,
        application: str,
        *,
        start_at: datetime,
        end_at: datetime,
    ) -> DeletionScope:
        _validate_window(start_at, end_at)
        _validate_application(application)
        return cls(
            kind=DeletionScopeKind.APPLICATION,
            application=application,
            start_at=start_at,
            end_at=end_at,
        )

    @classmethod
    def for_time_range(cls, *, start_at: datetime, end_at: datetime) -> DeletionScope:
        _validate_window(start_at, end_at)
        return cls(
            kind=DeletionScopeKind.TIME_RANGE,
            start_at=start_at,
            end_at=end_at,
        )

    def __post_init__(self) -> None:
        match self.kind:
            case DeletionScopeKind.RECORD_IDS:
                if self.record_ids == ():
                    raise ValueError("record scope requires at least one record ID")
            case DeletionScopeKind.ACTIVITY_CLUSTER:
                if self.cluster_id is None:
                    raise ValueError("cluster scope requires a cluster identifier")
            case DeletionScopeKind.APPLICATION:
                if self.application is None:
                    raise ValueError("application scope requires an application value")
            case DeletionScopeKind.TIME_RANGE:
                pass
            case _:
                raise ValueError("deletion scope kind is invalid")
        if self.kind is not DeletionScopeKind.RECORD_IDS and self.record_ids != ():
            raise ValueError("record IDs are only valid for a record scope")
        if self.kind is not DeletionScopeKind.ACTIVITY_CLUSTER and self.cluster_id is not None:
            raise ValueError("cluster identifier is only valid for a cluster scope")
        if self.kind is not DeletionScopeKind.APPLICATION and self.application is not None:
            raise ValueError("application value is only valid for an application scope")
        if self.kind not in {
            DeletionScopeKind.APPLICATION,
            DeletionScopeKind.TIME_RANGE,
        } and (self.start_at is not None or self.end_at is not None):
            raise ValueError("time bounds are only valid for bounded scopes")

    def __repr__(self) -> str:
        size = len(self.record_ids)
        return (
            f"DeletionScope(kind={self.kind.value!r}, record_count={size}, "
            f"cluster_id={self.cluster_id!r}, application=<redacted>, "
            f"start_at={self.start_at!r}, end_at={self.end_at!r})"
        )


class DeletionScopeResolver:
    """Resolve a closed typed scope to opaque record IDs with bounded work.

    Selection uses bounded candidate enumeration plus decrypt-on-demand and
    keeps decrypted records memory-only for the resolution lifetime. Only
    opaque record identifiers survive resolution.
    """

    def __init__(
        self,
        *,
        storage: QueryableStorageBackend,
        encryption: EncryptionProvider,
        activity_store: EncryptedActivityStore,
        candidate_limit: int = _MAX_SCOPE_RECORDS,
    ) -> None:
        if not 1 <= candidate_limit <= _MAX_SCOPE_RECORDS:
            raise ValueError("deletion scope candidate limit is invalid")
        self._storage = storage
        self._encryption = encryption
        self._activity_store = activity_store
        self._candidate_limit = candidate_limit

    def __repr__(self) -> str:
        return "DeletionScopeResolver(dependencies=redacted)"

    async def resolve(self, scope: DeletionScope) -> tuple[UUID, ...]:
        match scope.kind:
            case DeletionScopeKind.RECORD_IDS:
                return scope.record_ids
            case DeletionScopeKind.ACTIVITY_CLUSTER:
                return await self._resolve_cluster(scope)
            case DeletionScopeKind.APPLICATION:
                return await self._resolve_application(scope)
            case DeletionScopeKind.TIME_RANGE:
                return await self._resolve_time_range(scope)
        raise ScopeResolutionFailure("deletion scope kind is invalid")

    async def _resolve_cluster(self, scope: DeletionScope) -> tuple[UUID, ...]:
        assert scope.cluster_id is not None
        snapshot = await self._activity_store.load()
        if snapshot is None:
            raise ScopeResolutionFailure("deletion scope cluster is unknown")
        for entry in snapshot.entries:
            if cluster_identifier(entry) == scope.cluster_id:
                _validate_record_ids(entry.cluster.source_record_ids)
                return entry.cluster.source_record_ids
        raise ScopeResolutionFailure("deletion scope cluster is unknown")

    async def _resolve_application(self, scope: DeletionScope) -> tuple[UUID, ...]:
        assert scope.application is not None and scope.start_at is not None
        assert scope.end_at is not None
        expected = scope.application.casefold()
        selected: list[UUID] = []
        async for candidate in _candidates(
            self._storage,
            scope.start_at,
            scope.end_at,
            self._candidate_limit,
        ):
            record = await self._decrypt(candidate)
            if record is None:
                continue
            if _application_matches(record.frame.metadata, expected):
                selected.append(record.record_id)
                if len(selected) > self._candidate_limit:
                    raise ScopeResolutionFailure("deletion scope candidate limit exceeded")
        return _require_selected(selected)

    async def _resolve_time_range(self, scope: DeletionScope) -> tuple[UUID, ...]:
        assert scope.start_at is not None and scope.end_at is not None
        selected: list[UUID] = []
        async for candidate in _candidates(
            self._storage,
            scope.start_at,
            scope.end_at,
            self._candidate_limit,
        ):
            record = await self._decrypt(candidate)
            if record is None:
                continue
            if scope.start_at <= record.frame.captured_at < scope.end_at:
                selected.append(record.record_id)
                if len(selected) > self._candidate_limit:
                    raise ScopeResolutionFailure("deletion scope candidate limit exceeded")
        return _require_selected(selected)

    async def _decrypt(self, candidate: CatalogRecord) -> RedactedRecord | None:
        envelope = await self._storage.get(candidate.record.record_id)
        if envelope is None:
            return None
        record = await self._encryption.decrypt(DecryptionRequest(envelope, envelope.key))
        if record.record_id != candidate.record.record_id:
            raise ScopeResolutionFailure("decrypted record identity mismatch")
        return record


def cluster_identifier(entry: ActivityEntry) -> str:
    """Derive the stable opaque identifier of one activity cluster entry."""
    digest = hashlib.sha256()
    for source_id in entry.cluster.source_record_ids:
        digest.update(b"record:")
        digest.update(str(source_id).encode("ascii"))
    digest.update(b"started:")
    digest.update(entry.cluster.started_at.isoformat().encode("utf-8"))
    digest.update(b"ended:")
    digest.update(entry.cluster.ended_at.isoformat().encode("utf-8"))
    digest.update(b"fingerprint:")
    digest.update(entry.source_fingerprint.encode("ascii"))
    return digest.hexdigest()[:32]


async def _candidates(
    storage: QueryableStorageBackend,
    start_at: datetime,
    end_at: datetime,
    candidate_limit: int,
):
    start_day = start_at.astimezone(UTC).date()
    end_day = _inclusive_end_day(end_at)
    day = start_day
    scanned = 0
    while day <= end_day:
        found = await storage.list_candidates(
            DayRangeQuery(start_day=day, end_day=day, limit=_DAY_QUERY_LIMIT)
        )
        if len(found) >= _DAY_QUERY_LIMIT:
            raise ScopeResolutionFailure("deletion scope candidate limit exceeded")
        for candidate in found:
            scanned += 1
            if scanned > candidate_limit:
                raise ScopeResolutionFailure("deletion scope candidate limit exceeded")
            yield candidate
        day = day + _DAY


def _inclusive_end_day(end_at: datetime) -> date:
    last_instant = end_at.astimezone(UTC) - timedelta(microseconds=1)
    return last_instant.date()


def _require_selected(selected: list[UUID]) -> tuple[UUID, ...]:
    if not selected:
        raise ScopeResolutionFailure("deletion scope selects no records")
    return tuple(selected)


def _application_matches(metadata: ContextMetadata, expected: str) -> bool:
    value = metadata.get("application")
    return isinstance(value, str) and value.casefold() == expected


def _validate_record_ids(record_ids: tuple[UUID, ...]) -> None:
    if not record_ids:
        raise ValueError("deletion scope requires at least one record ID")
    if len(record_ids) > _MAX_SCOPE_RECORDS:
        raise ValueError("deletion scope exceeds the record limit")
    if len(set(record_ids)) != len(record_ids):
        raise ValueError("duplicate record IDs are not allowed")


def _validate_window(start_at: datetime, end_at: datetime) -> None:
    require_aware(start_at, "start_at")
    require_aware(end_at, "end_at")
    if end_at <= start_at:
        raise ValueError("deletion scope time window is invalid")
    if end_at - start_at > _MAX_SCOPE_SPAN_DAYS * _DAY:
        raise ValueError("deletion scope time window exceeds the span limit")


def _validate_application(application: str) -> None:
    if not application or len(application) > _MAX_APPLICATION_LENGTH:
        raise ValueError("deletion scope application value has invalid length")
    if any(character in "\r\n\x00" or ord(character) < 0x20 for character in application):
        raise ValueError("deletion scope application value contains invalid characters")
