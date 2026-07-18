from enum import StrEnum


class StorageFailureCode(StrEnum):
    INVALID_TYPE = "invalid_type"
    INVALID_RECORD_ID = "invalid_record_id"
    UNSAFE_ROOT = "unsafe_root"
    DUPLICATE_RECORD = "duplicate_record"
    QUOTA_EXCEEDED = "quota_exceeded"
    BLOB_TOO_LARGE = "blob_too_large"


class StorageFailure(RuntimeError):
    pass
