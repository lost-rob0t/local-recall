from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime

from ._validation import require_aware, require_nonempty

type MetadataScalar = str | int | float | bool | None
_FIELD_NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")


@dataclass(frozen=True, slots=True, order=True)
class SourceConfidence:
    value: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.value <= 1.0:
            raise ValueError("source confidence must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class MetadataProvenance:
    source_id: str
    observed_at: datetime
    confidence: SourceConfidence
    adapter_revision: str | None = None

    def __post_init__(self) -> None:
        require_nonempty(self.source_id, "source_id")
        require_aware(self.observed_at, "observed_at")
        if self.adapter_revision is not None:
            require_nonempty(self.adapter_revision, "adapter_revision")


@dataclass(frozen=True, slots=True)
class ContextField:
    name: str
    value: MetadataScalar = field(repr=False)
    provenance: tuple[MetadataProvenance, ...]

    def __post_init__(self) -> None:
        if not _FIELD_NAME.fullmatch(self.name):
            raise ValueError("metadata field name is invalid")
        if not self.provenance:
            raise ValueError("metadata field requires provenance")

    def __repr__(self) -> str:
        return f"ContextField(name={self.name!r}, provenance_count={len(self.provenance)})"


@dataclass(frozen=True, slots=True, repr=False)
class ContextMetadata:
    observed_at: datetime
    fields: tuple[ContextField, ...]

    def __post_init__(self) -> None:
        require_aware(self.observed_at, "observed_at")
        names: set[str] = set()
        for item in self.fields:
            if item.name in names:
                raise ValueError(f"duplicate metadata field: {item.name}")
            names.add(item.name)

    def get(self, name: str, default: MetadataScalar = None) -> MetadataScalar:
        for item in self.fields:
            if item.name == name:
                return item.value
        return default

    def __repr__(self) -> str:
        names = tuple(item.name for item in self.fields)
        return f"ContextMetadata(observed_at={self.observed_at!r}, fields={names!r})"
