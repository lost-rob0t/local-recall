"""Read-only diagnostic bundle assembled from sanitized inputs only."""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime

from local_recall.health.models import HealthReport

_MAX_REVISIONS = 16
_MAX_REVISION_LENGTH = 128
_SAFE_TOKEN = re.compile(r"^[a-z0-9][a-z0-9.-]{0,127}$")


def application_version() -> str:
    try:
        from importlib.metadata import version

        return version("local-recall")
    except Exception:
        return "unknown"


def _sanitize_revision(revision: object) -> str:
    if not isinstance(revision, str) or not revision or len(revision) > _MAX_REVISION_LENGTH:
        raise ValueError("diagnostic bundle revision is invalid")
    if any(character in revision for character in ("/", "\\", "\x00", " ", "=")):
        raise ValueError("diagnostic bundle revision is invalid")
    return revision


def _safe_result_token(value: object) -> str:
    if not isinstance(value, str) or _SAFE_TOKEN.fullmatch(value) is None:
        raise ValueError("diagnostic bundle result token is invalid")
    return value


@dataclass(frozen=True, slots=True, repr=False)
class DiagnosticBundle:
    generated_at: datetime
    application_version: str
    python_version: str
    platform_family: str
    results: tuple[tuple[str, str, str], ...]
    record_count: int
    storage_bytes: int
    revisions: tuple[str, ...] = field(default_factory=tuple[str, ...])
    storage_path: None = None

    def __post_init__(self) -> None:
        if self.generated_at.tzinfo is None or self.generated_at.utcoffset() is None:
            raise ValueError("diagnostic bundle timestamp must be timezone-aware")
        if self.record_count < 0 or self.storage_bytes < 0:
            raise ValueError("diagnostic bundle counts must be non-negative")
        if len(self.revisions) > _MAX_REVISIONS:
            raise ValueError("too many diagnostic bundle revisions")
        if self.platform_family != "linux":
            raise ValueError("diagnostic bundle platform is unsupported")

    def to_json(self) -> str:
        return json.dumps(
            {
                "generated_at": self.generated_at.isoformat(),
                "application_version": self.application_version,
                "python_version": self.python_version,
                "platform_family": self.platform_family,
                "results": [
                    {"check_id": check_id, "state": state, "reason_code": reason_code}
                    for check_id, state, reason_code in self.results
                ],
                "counts": {"records": self.record_count, "storage_bytes": self.storage_bytes},
                "revisions": list(self.revisions),
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def __repr__(self) -> str:
        return (
            f"DiagnosticBundle(generated_at={self.generated_at!r}, "
            f"results={len(self.results)}, content=redacted)"
        )


def build_diagnostic_bundle(
    report: HealthReport,
    *,
    now: Callable[[], datetime],
    record_count: int,
    storage_bytes: int,
    revisions: Sequence[str],
) -> DiagnosticBundle:
    return DiagnosticBundle(
        generated_at=now(),
        application_version=application_version(),
        python_version=".".join(str(part) for part in sys.version_info[:3]),
        platform_family=sys.platform,
        results=tuple(
            (
                _safe_result_token(result.check_id.value),
                _safe_result_token(result.state.value),
                _safe_result_token(result.reason_code),
            )
            for result in report.results
        ),
        record_count=record_count,
        storage_bytes=storage_bytes,
        revisions=tuple(_sanitize_revision(revision) for revision in revisions),
    )
