from __future__ import annotations

import ipaddress
import json
import math
from datetime import UTC, datetime
from typing import Protocol, cast
from urllib.parse import quote, urlencode, urlsplit

from local_recall.config.models import ActivityWatchURLMode, MetadataSettings

from .activitywatch_http import LoopbackActivityWatchTransport
from .activitywatch_types import (
    MAX_APPLICATION_CHARS,
    MAX_BUCKET_BODY_BYTES,
    MAX_BUCKET_ID_CHARS,
    MAX_BUCKETS,
    MAX_CLIENT_CHARS,
    MAX_DOMAIN_CHARS,
    MAX_EVENT_BODY_BYTES,
    MAX_EVENT_DURATION_SECONDS,
    MAX_EVENTS_PER_BUCKET,
    MAX_HOSTNAME_CHARS,
    MAX_INFO_BODY_BYTES,
    MAX_TITLE_CHARS,
    MAX_URL_CHARS,
    ActivityWatchAdapterFailure,
    ActivityWatchBucket,
    ActivityWatchEvent,
    ActivityWatchEventType,
    ActivityWatchMetadataFailureCode,
    ActivityWatchServerInfo,
    contains_control,
    require_aware,
    require_bounded_text,
    validate_domain,
)


class ActivityWatchTransport(Protocol):
    async def get(
        self,
        target: str,
        *,
        max_response_bytes: int,
        timeout_seconds: float | None = None,
    ) -> bytes: ...


class ActivityWatchClient(Protocol):
    async def server_info(
        self,
        *,
        timeout_seconds: float,
    ) -> ActivityWatchServerInfo: ...

    async def buckets(
        self,
        *,
        timeout_seconds: float,
    ) -> tuple[ActivityWatchBucket, ...]: ...

    async def events(
        self,
        bucket_id: str,
        *,
        start: datetime,
        end: datetime,
        limit: int,
        timeout_seconds: float,
    ) -> tuple[ActivityWatchEvent, ...]: ...


class LocalActivityWatchClient:
    def __init__(
        self,
        settings: MetadataSettings | None = None,
        *,
        transport: ActivityWatchTransport | None = None,
    ) -> None:
        self._settings = settings or MetadataSettings()
        activitywatch = self._settings.activitywatch
        self._transport = transport or LoopbackActivityWatchTransport(
            activitywatch.endpoint,
            connect_timeout_seconds=activitywatch.connect_timeout_seconds,
            request_timeout_seconds=activitywatch.request_timeout_seconds,
        )
        self._bucket_types: dict[str, ActivityWatchEventType] = {}

    async def server_info(
        self,
        *,
        timeout_seconds: float,
    ) -> ActivityWatchServerInfo:
        payload = await self._transport.get(
            "/api/0/info",
            max_response_bytes=MAX_INFO_BODY_BYTES,
            timeout_seconds=timeout_seconds,
        )
        value = _decode_object(payload)
        try:
            hostname = _required_text(
                value.get("hostname"),
                max_length=MAX_HOSTNAME_CHARS,
            )
            return ActivityWatchServerInfo(hostname=hostname)
        except ValueError:
            raise ActivityWatchAdapterFailure(
                ActivityWatchMetadataFailureCode.MALFORMED_RESPONSE
            ) from None

    async def buckets(
        self,
        *,
        timeout_seconds: float,
    ) -> tuple[ActivityWatchBucket, ...]:
        payload = await self._transport.get(
            "/api/0/buckets/",
            max_response_bytes=MAX_BUCKET_BODY_BYTES,
            timeout_seconds=timeout_seconds,
        )
        value = _decode_object(payload)
        if len(value) > MAX_BUCKETS:
            raise ActivityWatchAdapterFailure(ActivityWatchMetadataFailureCode.TOO_MANY_BUCKETS)

        parsed: list[ActivityWatchBucket] = []
        bucket_types: dict[str, ActivityWatchEventType] = {}
        for raw_id, raw_bucket in value.items():
            if not isinstance(raw_bucket, dict):
                continue
            bucket_mapping = cast(dict[str, object], raw_bucket)
            try:
                bucket_id = _required_text(
                    raw_id,
                    max_length=MAX_BUCKET_ID_CHARS,
                )
                raw_type = _required_text(
                    bucket_mapping.get("type"),
                    max_length=64,
                )
                try:
                    event_type = ActivityWatchEventType(raw_type)
                except ValueError:
                    continue
                client = _required_text(
                    bucket_mapping.get("client"),
                    max_length=MAX_CLIENT_CHARS,
                )
                hostname = _required_text(
                    bucket_mapping.get("hostname"),
                    max_length=MAX_HOSTNAME_CHARS,
                )
                created_at = _parse_timestamp(
                    _required_text(
                        bucket_mapping.get("created"),
                        max_length=64,
                    )
                )
                item = ActivityWatchBucket(
                    bucket_id=bucket_id,
                    event_type=event_type,
                    client=client,
                    hostname=hostname,
                    created_at=created_at,
                )
            except ValueError:
                continue
            parsed.append(item)
            bucket_types[item.bucket_id] = item.event_type

        self._bucket_types = bucket_types
        return tuple(parsed)

    async def events(
        self,
        bucket_id: str,
        *,
        start: datetime,
        end: datetime,
        limit: int,
        timeout_seconds: float,
    ) -> tuple[ActivityWatchEvent, ...]:
        require_aware(start)
        require_aware(end)
        if end <= start or not 1 <= limit <= MAX_EVENTS_PER_BUCKET:
            raise ActivityWatchAdapterFailure(ActivityWatchMetadataFailureCode.INVALID_REQUEST)

        event_type = self._bucket_types.get(bucket_id)
        if event_type is None:
            raise ActivityWatchAdapterFailure(ActivityWatchMetadataFailureCode.INVALID_REQUEST)

        query = urlencode(
            {
                "start": start.astimezone(UTC).isoformat(),
                "end": end.astimezone(UTC).isoformat(),
                "limit": str(limit),
            }
        )
        payload = await self._transport.get(
            f"/api/0/buckets/{quote(bucket_id, safe='')}/events?{query}",
            max_response_bytes=MAX_EVENT_BODY_BYTES,
            timeout_seconds=timeout_seconds,
        )
        values = _decode_list(payload)
        if len(values) > limit or len(values) > MAX_EVENTS_PER_BUCKET:
            raise ActivityWatchAdapterFailure(ActivityWatchMetadataFailureCode.MALFORMED_RESPONSE)

        parsed: list[ActivityWatchEvent] = []
        for raw_event in values:
            try:
                item = self._parse_event(event_type, raw_event)
            except ValueError:
                continue
            if item is not None:
                parsed.append(item)
        return tuple(parsed)

    def _parse_event(
        self,
        event_type: ActivityWatchEventType,
        raw_event: object,
    ) -> ActivityWatchEvent | None:
        if not isinstance(raw_event, dict):
            return None
        value = cast(dict[str, object], raw_event)

        timestamp = _parse_timestamp(
            _required_text(
                value.get("timestamp"),
                max_length=64,
            )
        )
        duration = _duration(value.get("duration"))
        raw_data = value.get("data")
        if not isinstance(raw_data, dict):
            return None
        data = cast(dict[str, object], raw_data)

        if event_type is ActivityWatchEventType.CURRENT_WINDOW:
            application = _optional_text(
                data.get("app"),
                max_length=MAX_APPLICATION_CHARS,
            )
            title = None
            if self._settings.window_titles_enabled:
                title = _optional_text(
                    data.get("title"),
                    max_length=MAX_TITLE_CHARS,
                )
            if application is None and title is None:
                return None
            return ActivityWatchEvent(
                event_type=event_type,
                timestamp=timestamp,
                duration_seconds=duration,
                application=application,
                title=title,
            )

        if event_type is ActivityWatchEventType.AFK_STATUS:
            status = _required_text(data.get("status"), max_length=16)
            if status == "afk":
                idle = True
            elif status == "not-afk":
                idle = False
            else:
                return None
            return ActivityWatchEvent(
                event_type=event_type,
                timestamp=timestamp,
                duration_seconds=duration,
                idle=idle,
            )

        if self._settings.activitywatch.url_mode is not ActivityWatchURLMode.DOMAIN_ONLY:
            return None
        raw_url = _required_text(
            data.get("url"),
            max_length=MAX_URL_CHARS,
        )
        domain = _domain_from_url(raw_url)
        if domain is None:
            return None
        return ActivityWatchEvent(
            event_type=event_type,
            timestamp=timestamp,
            duration_seconds=duration,
            domain=domain,
        )


def _decode_json(payload: bytes) -> object:
    def reject_duplicates(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError
            value[key] = item
        return value

    try:
        return cast(
            object,
            json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=reject_duplicates,
            ),
        )
    except UnicodeDecodeError, ValueError, json.JSONDecodeError:
        raise ActivityWatchAdapterFailure(ActivityWatchMetadataFailureCode.INVALID_JSON) from None


def _decode_object(payload: bytes) -> dict[str, object]:
    value = _decode_json(payload)
    if not isinstance(value, dict):
        raise ActivityWatchAdapterFailure(ActivityWatchMetadataFailureCode.MALFORMED_RESPONSE)
    return cast(dict[str, object], value)


def _decode_list(payload: bytes) -> list[object]:
    value = _decode_json(payload)
    if not isinstance(value, list):
        raise ActivityWatchAdapterFailure(ActivityWatchMetadataFailureCode.MALFORMED_RESPONSE)
    return cast(list[object], value)


def _required_text(
    value: object,
    *,
    max_length: int,
) -> str:
    normalized = _optional_text(
        value,
        max_length=max_length,
    )
    if normalized is None:
        raise ValueError("ActivityWatch text field is invalid")
    return normalized


def _optional_text(
    value: object,
    *,
    max_length: int,
) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("ActivityWatch text field is invalid")
    require_bounded_text(value, max_length)
    return value


def _duration(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("ActivityWatch duration is invalid")
    normalized = float(value)
    if not math.isfinite(normalized) or normalized < 0.0 or normalized > MAX_EVENT_DURATION_SECONDS:
        raise ValueError("ActivityWatch duration is invalid")
    return normalized


def _parse_timestamp(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        raise ValueError("ActivityWatch timestamp is invalid") from None
    require_aware(parsed)
    return parsed.astimezone(UTC)


def _domain_from_url(raw_url: str) -> str | None:
    if len(raw_url) > MAX_URL_CHARS or contains_control(raw_url):
        return None

    try:
        parsed = urlsplit(raw_url)
        hostname = parsed.hostname
        parsed.port
    except ValueError:
        return None

    if (
        parsed.scheme not in {"http", "https"}
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        return None

    try:
        domain = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None

    if len(domain) > MAX_DOMAIN_CHARS:
        return None
    try:
        validate_domain(domain)
    except ValueError:
        return None
    return domain
