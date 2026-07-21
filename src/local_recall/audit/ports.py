from __future__ import annotations

from typing import Protocol, runtime_checkable

from .models import AuditEvent


@runtime_checkable
class AuditSink(Protocol):
    def emit(self, event: AuditEvent) -> None: ...
