"""Encrypted backup export and restore engine."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from uuid import UUID

from local_recall.audit.models import AuditReasonCode
from local_recall.audit.recorder import AuditRecorder
from local_recall.backup.archive import BackupArchive, RestoreFailure
from local_recall.domain.crypto import EncryptedRecordEnvelope
from local_recall.ports.keys import KeyProvider
from local_recall.retention.planner import RetentionStorage
from local_recall.storage import CURRENT_STORAGE_SCHEMA_VERSION, SQLiteEncryptedStorage
from local_recall.storage.codec import encode_envelope
from local_recall.storage.errors import StorageFailure, StorageFailureCode


@dataclass(frozen=True, slots=True)
class ExportResult:
    record_count: int
    archive_path: Path


@dataclass(frozen=True, slots=True)
class RestoreResult:
    restored_count: int
    skipped_duplicates: int


class BackupEngine:
    """Export and restore encrypted record archives without plaintext access.

    Archives contain only canonical encrypted envelopes plus a sanitized
    manifest (format/schema versions, record count, body digest). No active
    key material, captured text, thumbnails, prompts, or credentials are
    included. Export and restore are audited with counts only.
    """

    def __init__(
        self,
        *,
        source_storage: RetentionStorage,
        audit: AuditRecorder | None = None,
        key_provider: KeyProvider | None = None,
        max_blob_bytes: int = 1_000_000,
        crypter: object | None = None,
    ) -> None:
        self._storage = source_storage
        self._audit = audit
        self._key_provider = key_provider
        self._max_blob_bytes = max_blob_bytes
        self.crypter = crypter

    def __repr__(self) -> str:
        return "BackupEngine(dependencies=redacted)"

    async def export(
        self,
        path: Path,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> ExportResult:
        envelopes = await self._collect(start=start, end=end)
        BackupArchive.write(
            path,
            envelopes=tuple(envelopes),
            created_at=datetime.now(UTC).isoformat(),
            schema_version=CURRENT_STORAGE_SCHEMA_VERSION,
            max_blob_bytes=self._max_blob_bytes,
        )
        if self.crypter is not None:
            payload = await self.crypter.encrypt(path.read_bytes())
            if not payload:
                self._audit_export(count=0, succeeded=False)
                raise RestoreFailure("archive encryption failed")
            path.write_bytes(payload)
        self._audit_export(count=len(envelopes), succeeded=True)
        return ExportResult(record_count=len(envelopes), archive_path=path)

    async def restore(
        self,
        path: Path,
        target: SQLiteEncryptedStorage,
        *,
        allow_non_empty: bool = False,
    ) -> RestoreResult:
        if self.crypter is not None:
            path.write_bytes(await self.crypter.decrypt(path.read_bytes()))
        usage = await target.stats()
        if usage.ready_records > 0 and not allow_non_empty:
            raise RestoreFailure("restore target is not empty")
        archive = BackupArchive.read(
            path,
            max_blob_bytes=self._max_blob_bytes,
            expected_schema_version=CURRENT_STORAGE_SCHEMA_VERSION,
        )
        restored = 0
        skipped = 0
        seen: set[UUID] = set()
        for envelope in archive.envelopes:
            if envelope.record_id in seen:
                skipped += 1
                continue
            seen.add(envelope.record_id)
            existing = await target.get(envelope.record_id)
            if existing is not None:
                if encode_envelope(existing) != encode_envelope(envelope):
                    self._audit_restore(count=0, succeeded=False)
                    raise RestoreFailure("conflicting duplicate record")
                skipped += 1
                continue
            try:
                await target.put(envelope)
                restored += 1
            except StorageFailure as exc:
                if exc.code is StorageFailureCode.DUPLICATE_RECORD:
                    self._audit_restore(count=0, succeeded=False)
                    raise RestoreFailure("conflicting duplicate record") from exc
                self._audit_restore(count=0, succeeded=False)
                raise RestoreFailure("restore failed safely") from exc
        self._audit_restore(count=restored, succeeded=True)
        return RestoreResult(restored_count=restored, skipped_duplicates=skipped)

    async def _collect(
        self,
        *,
        start: datetime | None,
        end: datetime | None,
    ) -> list[EncryptedRecordEnvelope]:
        envelopes: list[EncryptedRecordEnvelope] = []
        after_day: date | None = None
        after_id: UUID | None = None
        while True:
            page = await self._storage.page_ready(
                after_day=after_day,
                after_id=after_id,
                limit=10_000,
            )
            for entry in page.entries:
                if start is not None and entry.day_bucket < start.astimezone(UTC).date():
                    continue
                if end is not None and entry.day_bucket > end.astimezone(UTC).date():
                    continue
                envelope = await self._storage.get(entry.record_id)
                if envelope is not None:
                    envelopes.append(envelope)
            if page.complete:
                return envelopes
            last = page.entries[-1]
            after_day = last.day_bucket
            after_id = last.record_id

    def _audit_export(self, *, count: int, succeeded: bool) -> None:
        if self._audit is not None:
            self._audit.export_decision(
                allowed=succeeded,
                reason=AuditReasonCode.EXPORT_ALLOWED,
                count=count,
            )

    def _audit_restore(self, *, count: int, succeeded: bool) -> None:
        if self._audit is not None:
            self._audit.restore_decision(count=count, succeeded=succeeded)
