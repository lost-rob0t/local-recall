from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import StrEnum
from uuid import UUID

from local_recall.domain.crypto import KeyHandle


class CatalogState(StrEnum):
    READY = "ready"
    DELETING = "deleting"
    QUARANTINED = "quarantined"


@dataclass(frozen=True, slots=True)
class DayRangeQuery:
    start_day: date
    end_day: date
    limit: int = 1000

    def __post_init__(self) -> None:
        if self.end_day < self.start_day:
            raise ValueError("end_day must not precede start_day")
        if not 1 <= self.limit <= 10000:
            raise ValueError("limit must be between 1 and 10000")


@dataclass(frozen=True, slots=True)
class CatalogRecord:
    record_id: UUID
    day_bucket: date
    envelope_schema_version: int
    key: KeyHandle
    ciphertext_bytes: int
    blob_bytes: int

    def __post_init__(self) -> None:
        if self.record_id.version != 4:
            raise ValueError("catalog record ID must be UUIDv4")
        if self.envelope_schema_version <= 0:
            raise ValueError("envelope schema version must be positive")
        if self.ciphertext_bytes <= 0 or self.blob_bytes <= 0:
            raise ValueError("catalog byte lengths must be positive")
        if self.blob_bytes < self.ciphertext_bytes:
            raise ValueError("blob bytes must not be less than ciphertext bytes")


@dataclass(frozen=True, slots=True)
class RecoveryReport:
    promoted_write_intents: int = 0
    discarded_write_intents: int = 0
    temporary_files_removed: int = 0
    quarantined_blobs: int = 0
    completed_deletions: int = 0

    def __post_init__(self) -> None:
        values = (
            self.promoted_write_intents,
            self.discarded_write_intents,
            self.temporary_files_removed,
            self.quarantined_blobs,
            self.completed_deletions,
        )
        if any(value < 0 for value in values):
            raise ValueError("recovery counters must not be negative")
