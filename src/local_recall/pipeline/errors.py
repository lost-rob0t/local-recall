from __future__ import annotations

from uuid import UUID


class PipelineError(RuntimeError):
    """Base pipeline failure with sanitized messages."""


class PipelineClosed(PipelineError):
    pass


class PipelineOwnershipError(PipelineError):
    pass


class PipelineProtocolError(PipelineError):
    def __init__(self, message: str, *, record_id: UUID | None = None) -> None:
        prefix = f"record {record_id}: " if record_id is not None else ""
        super().__init__(prefix + message)
        self.record_id = record_id
