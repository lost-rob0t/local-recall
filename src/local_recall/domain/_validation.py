from __future__ import annotations

from datetime import datetime


def require_aware(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")


def require_nonempty(value: str, field_name: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"{field_name} must not be empty")


def require_nonempty_bytes(value: bytes, field_name: str) -> None:
    if not value:
        raise ValueError(f"{field_name} must not be empty")
