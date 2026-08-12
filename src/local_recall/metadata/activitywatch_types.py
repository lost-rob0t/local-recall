from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

MAX_BUCKETS = 32
MAX_CANDIDATES_PER_TYPE = 8
MAX_EVENTS_PER_BUCKET = 16
MAX_HEADER_BYTES = 16 * 1024
MAX_INFO_BODY_BYTES = 16 * 1024
MAX_BUCKET_BODY_BYTES = 256 * 1024
MAX_EVENT_BODY_BYTES = 128 * 1024
MAX_BUCKET_ID_CHARS = 512
MAX_CLIENT_CHARS = 128
MAX_HOSTNAME_CHARS = 255
MAX_APPLICATION_CHARS = 256
MAX_TITLE_CHARS = 4096
MAX_URL_CHARS = 4096
MAX_DOMAIN_CHARS = 253
MAX_EVENT_DURATION_SECONDS = 24 * 60 * 60
ADAPTER_REVISION = "activitywatch-api0-v1"
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class ActivityWatchEventType(StrEnum):
    CURRENT_WINDOW = "currentwindow"
    AFK_STATUS = "afkstatus"
    WEB_TAB_CURRENT = "web.tab.current"


class ActivityWatchMetadataFailureCode(StrEnum):
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    INVALID_REQUEST = "invalid-request"
    HEADERS_TOO_LARGE = "headers-too-large"
    RESPONSE_TOO_LARGE = "response-too-large"
    MALFORMED_HTTP = "malformed-http"
    INVALID_CONTENT_LENGTH = "invalid-content-length"
    INCOMPLETE_RESPONSE = "incomplete-response"
    HTTP_STATUS = "http-status"
    REDIRECT = "redirect"
    INVALID_JSON = "invalid-json"
    MALFORMED_RESPONSE = "malformed-response"
    TOO_MANY_BUCKETS = "too-many-buckets"
    NO_COMPATIBLE_BUCKETS = "no-compatible-buckets"
    AMBIGUOUS_BUCKETS = "ambiguous-buckets"
    NO_CORRELATED_EVENT = "no-correlated-event"


class ActivityWatchAdapterFailure(RuntimeError):
    def __init__(self, code: ActivityWatchMetadataFailureCode) -> None:
        self.code = code
        super().__init__(f"ActivityWatch adapter failed: {code.value}")

    def __repr__(self) -> str:
        return f"ActivityWatchAdapterFailure(code={self.code.value!r})"


class ActivityWatchMetadataFailure(RuntimeError):
    def __init__(self, code: ActivityWatchMetadataFailureCode) -> None:
        self.code = code
        super().__init__(f"ActivityWatch metadata failed: {code.value}")

    def __repr__(self) -> str:
        return f"ActivityWatchMetadataFailure(code={self.code.value!r})"


@dataclass(frozen=True, slots=True)
class ActivityWatchServerInfo:
    hostname: str

    def __post_init__(self) -> None:
        require_bounded_text(self.hostname, MAX_HOSTNAME_CHARS)

    def __repr__(self) -> str:
        return "ActivityWatchServerInfo(hostname=<redacted>)"


@dataclass(frozen=True, slots=True)
class ActivityWatchBucket:
    bucket_id: str
    event_type: ActivityWatchEventType
    client: str
    hostname: str
    created_at: datetime

    def __post_init__(self) -> None:
        require_bounded_text(self.bucket_id, MAX_BUCKET_ID_CHARS)
        require_bounded_text(self.client, MAX_CLIENT_CHARS)
        require_bounded_text(self.hostname, MAX_HOSTNAME_CHARS)
        require_aware(self.created_at)

    def __repr__(self) -> str:
        return (
            "ActivityWatchBucket("
            f"event_type={self.event_type.value!r}, "
            f"created_at={self.created_at!r}, "
            "identity=<redacted>)"
        )


@dataclass(frozen=True, slots=True)
class ActivityWatchEvent:
    event_type: ActivityWatchEventType
    timestamp: datetime
    duration_seconds: float
    application: str | None = None
    title: str | None = None
    idle: bool | None = None
    domain: str | None = None

    def __post_init__(self) -> None:
        require_aware(self.timestamp)
        if (
            isinstance(self.duration_seconds, bool)
            or not math.isfinite(self.duration_seconds)
            or self.duration_seconds < 0.0
            or self.duration_seconds > MAX_EVENT_DURATION_SECONDS
        ):
            raise ValueError("ActivityWatch event duration is invalid")
        if self.application is not None:
            require_bounded_text(self.application, MAX_APPLICATION_CHARS)
        if self.title is not None:
            require_bounded_text(self.title, MAX_TITLE_CHARS)
        if self.domain is not None:
            validate_domain(self.domain)

    def __repr__(self) -> str:
        return (
            "ActivityWatchEvent("
            f"event_type={self.event_type.value!r}, "
            f"timestamp={self.timestamp!r}, "
            f"duration_seconds={self.duration_seconds!r}, "
            "content=<redacted>)"
        )


def require_bounded_text(value: str, max_length: int) -> None:
    if (
        not value.strip()
        or len(value) > max_length
        or _CONTROL.search(value) is not None
    ):
        raise ValueError("ActivityWatch text field is invalid")


def require_aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("ActivityWatch timestamp must be timezone-aware")


def contains_control(value: str) -> bool:
    return _CONTROL.search(value) is not None


def validate_domain(value: str) -> None:
    if (
        not value
        or len(value) > MAX_DOMAIN_CHARS
        or contains_control(value)
    ):
        raise ValueError("ActivityWatch domain is invalid")
    labels = value.split(".")
    if any(
        not label
        or len(label) > 63
        or label[0] == "-"
        or label[-1] == "-"
        or re.fullmatch(r"[a-z0-9-]+", label) is None
        for label in labels
    ):
        raise ValueError("ActivityWatch domain is invalid")
