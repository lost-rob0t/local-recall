from __future__ import annotations

from enum import StrEnum
from uuid import UUID


class StorageFailureCode(StrEnum):
    INVALID_TYPE = "invalid_type"
    INVALID_RECORD_ID = "invalid_record_id"
    UNSAFE_ROOT = "unsafe_root"
    DUPLICATE_RECORD = "duplicate_record"
    QUOTA_EXCEEDED = "quota_exceeded"
    BLOB_TOO_LARGE = "blob_too_large"
    IO_FAILURE = "io_failure"
    CATALOG_FAILURE = "catalog_failure"
    CORRUPTION = "corruption"
    MIGRATION_FAILURE = "migration_failure"


class StorageFailure(RuntimeError):
    def __init__(self, code: StorageFailureCode, *, record_id: UUID | None = None) -> None:
        self.code = code
        self.record_id = record_id
        suffix = f":{record_id}" if record_id is not None else ""
        super().__init__(f"storage_{code.value}{suffix}")
