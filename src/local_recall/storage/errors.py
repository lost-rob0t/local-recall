from __future__ import annotations

from enum import StrEnum
from uuid import UUID


class StorageFailureCode(StrEnum):
    IO_FAILURE = "io_failure"
    PERMISSION_DENIED = "permission_denied"
    QUOTA_EXCEEDED = "quota_exceeded"
    CORRUPT_RECORD = "corrupt_record"
    UNSUPPORTED_SCHEMA = "unsupported_schema"
    CATALOG_FAILURE = "catalog_failure"
    RECORD_CONFLICT = "record_conflict"


class StorageFailure(RuntimeError):
    def __init__(
        self,
        record_id: UUID | None,
        code: StorageFailureCode,
    ) -> None:
        self.record_id = record_id
        self.code = code
        identity = "none" if record_id is None else str(record_id)
        super().__init__(f"storage_failure:{code.value}:{identity}")
