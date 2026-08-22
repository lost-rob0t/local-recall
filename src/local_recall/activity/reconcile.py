from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Protocol
from uuid import UUID

from local_recall.domain.frames import RedactedRecord
from local_recall.domain.metadata import ContextField

from .clustering import ActivitySegmenter
from .features import ActivityFeatureExtractor
from .store import ActivityEntry, ActivitySnapshot, EncryptedActivityStore
from .summaries import (
    ActivitySummarizer,
    ActivitySummary,
    ActivitySummaryUnavailable,
)


class _Digest(Protocol):
    def update(self, value: bytes, /) -> None: ...


class ActivityReconciler:
    __slots__ = ("_feature_extractor", "_segmenter", "_store", "_summarizer", "_lock")

    def __init__(
        self,
        *,
        feature_extractor: ActivityFeatureExtractor,
        segmenter: ActivitySegmenter,
        summarizer: ActivitySummarizer,
        store: EncryptedActivityStore,
    ) -> None:
        self._feature_extractor = feature_extractor
        self._segmenter = segmenter
        self._summarizer = summarizer
        self._store = store
        self._lock = asyncio.Lock()

    def __repr__(self) -> str:
        return "ActivityReconciler(dependencies=redacted)"

    async def reconcile(self, records: tuple[RedactedRecord, ...]) -> ActivitySnapshot:
        async with self._lock:
            previous = await self._store.load()
            if not records:
                replacement = ActivitySnapshot(entries=())
                await self._store.replace(replacement)
                return replacement

            record_by_id = _validate_records(records)
            features = await self._feature_extractor.extract(records)
            clusters = self._segmenter.segment(features)
            previous_entries = _previous_entries(previous)
            entries: list[ActivityEntry] = []
            for cluster in clusters:
                cluster_records = tuple(record_by_id[source_id] for source_id in cluster.source_record_ids)
                fingerprint = _source_fingerprint(cluster_records)
                policy_revisions = _policy_revisions(cluster_records)
                prior = previous_entries.get((cluster.source_record_ids, fingerprint))
                summary: ActivitySummary | None
                if prior is not None and prior.summary is not None:
                    summary = prior.summary
                else:
                    try:
                        summary = await self._summarizer.summarize(cluster, cluster_records)
                    except ActivitySummaryUnavailable:
                        summary = None
                entries.append(
                    ActivityEntry(
                        cluster=cluster,
                        summary=summary,
                        policy_revisions=policy_revisions,
                        source_fingerprint=fingerprint,
                    )
                )

            replacement = ActivitySnapshot(entries=tuple(entries))
            await self._store.replace(replacement)
            return replacement


def _validate_records(records: tuple[RedactedRecord, ...]) -> dict[UUID, RedactedRecord]:
    record_by_id = {record.record_id: record for record in records}
    if len(record_by_id) != len(records):
        raise ValueError("activity reconciliation requires unique record IDs")
    return record_by_id


def _previous_entries(
    snapshot: ActivitySnapshot | None,
) -> dict[tuple[tuple[UUID, ...], str], ActivityEntry]:
    if snapshot is None:
        return {}
    return {
        (entry.cluster.source_record_ids, entry.source_fingerprint): entry for entry in snapshot.entries
    }


def _policy_revisions(records: tuple[RedactedRecord, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(record.frame.policy_revision for record in records))


def _source_fingerprint(records: tuple[RedactedRecord, ...]) -> str:
    digest = hashlib.sha256()
    for record in records:
        _hash_text(digest, str(record.record_id))
        _hash_text(digest, record.frame.captured_at.isoformat())
        _hash_text(digest, record.frame.policy_revision)
        _hash_text(digest, str(record.frame.width))
        _hash_text(digest, str(record.frame.height))
        _hash_text(digest, str(record.frame.stride))
        _hash_text(digest, record.frame.pixel_format.value)
        _hash_bytes(digest, record.frame.pixels)
        for text in record.frame.ocr_text:
            _hash_text(digest, text)
        for field in sorted(record.frame.metadata.fields, key=lambda item: item.name):
            _hash_field(digest, field)
    return digest.hexdigest()


def _hash_field(digest: _Digest, field: ContextField) -> None:
    _hash_text(digest, field.name)
    encoded = json.dumps(field.value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    _hash_text(digest, encoded)


def _hash_text(digest: _Digest, value: str) -> None:
    _hash_bytes(digest, value.encode("utf-8"))


def _hash_bytes(digest: _Digest, value: bytes) -> None:
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)
