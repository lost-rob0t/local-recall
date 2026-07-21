from __future__ import annotations

from enum import StrEnum


class AuditFailureCode(StrEnum):
    INVALID_EVENT = "invalid_event"
    UNSAFE_PATH = "unsafe_path"
    INSECURE_PERMISSIONS = "insecure_permissions"
    IO_FAILURE = "io_failure"
    EVENT_TOO_LARGE = "event_too_large"
    HARDENING_FAILURE = "hardening_failure"


class AuditFailure(RuntimeError):
    def __init__(self, code: AuditFailureCode) -> None:
        self.code = code
        super().__init__(code.value)
