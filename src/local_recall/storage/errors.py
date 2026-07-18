from enum import StrEnum


class StorageFailureCode(StrEnum):
    INVALID_TYPE = "invalid_type"


class StorageFailure(RuntimeError):
    pass
