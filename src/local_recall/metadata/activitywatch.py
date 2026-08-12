from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta

from local_recall.config.models import ActivityWatchURLMode, MetadataSettings
from local_recall.domain.capture import MetadataRequest
from local_recall.domain.metadata import (
    ContextField,
    ContextMetadata,
    MetadataProvenance,
    SourceConfidence,
)

from .activitywatch_client import ActivityWatchClient, LocalActivityWatchClient
from .activitywatch_types import (
    ADAPTER_REVISION,
    MAX_BUCKETS,
    MAX_CANDIDATES_PER_TYPE,
    MAX_EVENTS_PER_BUCKET,
    ActivityWatchAdapterFailure,
    ActivityWatchBucket,
    ActivityWatchEvent,
    ActivityWatchEventType,
    ActivityWatchMetadataFailure,
    ActivityWatchMetadataFailureCode,
    require_aware,
)


class ActivityWatchMetadataSource:
    def __init__(
        self,
        settings: MetadataSettings | None = None,
        *,
        client: ActivityWatchClient | None = None,
        now: Callable[[], datetime] | None = None,
        monotonic_ns: Callable[[], int] | None = None,
    ) -> None:
        self._settings = settings or MetadataSettings()
        self._client = client or LocalActivityWatchClient(self._settings)
        self._now = now or (lambda: datetime.now(UTC))
        self._monotonic_ns = monotonic_ns or time.monotonic_ns

    @property
    def source_id(self) -> str:
        return "activitywatch"

    async def is_available(self) -> bool:
        try:
            return bool(await self.probe_capabilities())
        except asyncio.CancelledError:
            raise
        except Exception:
            return False

    async def probe_capabilities(self) -> frozenset[str]:
        timeout_seconds = self._settings.activitywatch.request_timeout_seconds
        info = await self._client.server_info(
            timeout_seconds=timeout_seconds,
        )
        buckets = await self._client.buckets(
            timeout_seconds=timeout_seconds,
        )
        scoped = _scope_buckets(buckets, info.hostname)
        capabilities: set[str] = set()
        for event_type, candidates in scoped.items():
            if not candidates:
                continue
            if event_type is ActivityWatchEventType.CURRENT_WINDOW:
                capabilities.add("application")
                if self._settings.window_titles_enabled:
                    capabilities.add("window-title")
            elif event_type is ActivityWatchEventType.AFK_STATUS:
                capabilities.update({"activity", "idle"})
            elif (
                event_type is ActivityWatchEventType.WEB_TAB_CURRENT
                and self._settings.activitywatch.url_mode is ActivityWatchURLMode.DOMAIN_ONLY
            ):
                capabilities.add("domain")
        return frozenset(capabilities)

    async def collect(
        self,
        request: MetadataRequest,
    ) -> ContextMetadata:
        observed_at = self._now()
        require_aware(observed_at)
        wanted = self._wanted_event_types(request)
        if not wanted:
            return ContextMetadata(observed_at=observed_at, fields=())
        self._remaining_timeout(request)

        try:
            info = await self._client.server_info(
                timeout_seconds=self._remaining_timeout(request),
            )
            buckets = await self._client.buckets(
                timeout_seconds=self._remaining_timeout(request),
            )
            relevant = tuple(item for item in buckets if item.event_type in wanted)
            scoped = _scope_buckets(relevant, info.hostname)
            if not any(scoped.get(event_type) for event_type in wanted):
                raise ActivityWatchMetadataFailure(
                    ActivityWatchMetadataFailureCode.NO_COMPATIBLE_BUCKETS
                )

            tolerance = self._settings.activitywatch.correlation_window_seconds
            start = observed_at - timedelta(seconds=tolerance)
            end = observed_at + timedelta(seconds=tolerance)
            selected: dict[
                ActivityWatchEventType,
                ActivityWatchEvent,
            ] = {}

            for event_type in sorted(wanted, key=lambda item: item.value):
                candidates = scoped.get(event_type, ())
                if not candidates:
                    continue
                event = await self._best_from_buckets(
                    candidates,
                    expected_type=event_type,
                    observed_at=observed_at,
                    start=start,
                    end=end,
                    tolerance_seconds=tolerance,
                    request=request,
                )
                if event is not None:
                    selected[event_type] = event

            fields = self._fields_from_events(
                selected,
                request=request,
                observed_at=observed_at,
            )
            if not fields:
                raise ActivityWatchMetadataFailure(
                    ActivityWatchMetadataFailureCode.NO_CORRELATED_EVENT
                )
            return ContextMetadata(
                observed_at=observed_at,
                fields=tuple(sorted(fields, key=lambda item: item.name)),
            )
        except asyncio.CancelledError:
            raise
        except ActivityWatchMetadataFailure:
            raise
        except ActivityWatchAdapterFailure as exc:
            raise ActivityWatchMetadataFailure(exc.code) from None
        except TimeoutError:
            raise ActivityWatchMetadataFailure(ActivityWatchMetadataFailureCode.TIMEOUT) from None
        except Exception:
            raise ActivityWatchMetadataFailure(
                ActivityWatchMetadataFailureCode.UNAVAILABLE
            ) from None

    def _remaining_timeout(
        self,
        request: MetadataRequest,
    ) -> float:
        remaining_ns = request.deadline_monotonic_ns - self._monotonic_ns()
        if remaining_ns <= 0:
            raise ActivityWatchMetadataFailure(ActivityWatchMetadataFailureCode.TIMEOUT)
        return min(
            remaining_ns / 1_000_000_000,
            self._settings.activitywatch.request_timeout_seconds,
        )

    def _wanted_event_types(
        self,
        request: MetadataRequest,
    ) -> frozenset[ActivityWatchEventType]:
        requested = request.requested_fields
        all_fields = not requested
        wanted: set[ActivityWatchEventType] = set()

        if (
            all_fields
            or "application" in requested
            or (self._settings.window_titles_enabled and "window.title" in requested)
        ):
            wanted.add(ActivityWatchEventType.CURRENT_WINDOW)

        if all_fields or "idle" in requested or "idle.seconds" in requested:
            wanted.add(ActivityWatchEventType.AFK_STATUS)

        if self._settings.activitywatch.url_mode is ActivityWatchURLMode.DOMAIN_ONLY and (
            all_fields or "url.domain" in requested
        ):
            wanted.add(ActivityWatchEventType.WEB_TAB_CURRENT)

        return frozenset(wanted)

    async def _best_from_buckets(
        self,
        buckets: tuple[ActivityWatchBucket, ...],
        *,
        expected_type: ActivityWatchEventType,
        observed_at: datetime,
        start: datetime,
        end: datetime,
        tolerance_seconds: float,
        request: MetadataRequest,
    ) -> ActivityWatchEvent | None:
        choices: list[
            tuple[
                tuple[float, float, float, str],
                ActivityWatchEvent,
            ]
        ] = []

        for bucket in buckets:
            events = await self._client.events(
                bucket.bucket_id,
                start=start,
                end=end,
                limit=MAX_EVENTS_PER_BUCKET,
                timeout_seconds=self._remaining_timeout(request),
            )
            event = _correlate_event(
                events,
                expected_type=expected_type,
                observed_at=observed_at,
                tolerance_seconds=tolerance_seconds,
            )
            if event is None:
                continue
            choices.append(
                (
                    (
                        _event_distance_seconds(event, observed_at),
                        -event.timestamp.timestamp(),
                        -bucket.created_at.timestamp(),
                        bucket.bucket_id,
                    ),
                    event,
                )
            )

        if not choices:
            return None
        return min(choices, key=lambda item: item[0])[1]

    def _fields_from_events(
        self,
        events: Mapping[
            ActivityWatchEventType,
            ActivityWatchEvent,
        ],
        *,
        request: MetadataRequest,
        observed_at: datetime,
    ) -> list[ContextField]:
        requested = request.requested_fields
        all_fields = not requested
        values: list[tuple[str, str | bool | float, float]] = []

        window = events.get(ActivityWatchEventType.CURRENT_WINDOW)
        if window is not None:
            if (all_fields or "application" in requested) and window.application is not None:
                values.append(
                    (
                        "application",
                        _normalize_application(window.application),
                        0.92,
                    )
                )
            if (
                self._settings.window_titles_enabled
                and (all_fields or "window.title" in requested)
                and window.title is not None
            ):
                values.append(("window.title", window.title, 0.90))

        afk = events.get(ActivityWatchEventType.AFK_STATUS)
        if afk is not None and (all_fields or "idle" in requested) and afk.idle is not None:
            values.append(("idle", afk.idle, 0.98))
        if afk is not None and "idle.seconds" in requested and afk.idle is not None:
            values.append(
                (
                    "idle.seconds",
                    afk.duration_seconds if afk.idle else 0.0,
                    0.98,
                )
            )

        web = events.get(ActivityWatchEventType.WEB_TAB_CURRENT)
        if (
            web is not None
            and self._settings.activitywatch.url_mode is ActivityWatchURLMode.DOMAIN_ONLY
            and (all_fields or "url.domain" in requested)
            and web.domain is not None
        ):
            values.append(("url.domain", web.domain, 0.86))

        fields: list[ContextField] = []
        for name, value, confidence in values:
            fields.append(
                ContextField(
                    name=name,
                    value=value,
                    provenance=(
                        MetadataProvenance(
                            source_id=self.source_id,
                            observed_at=observed_at,
                            confidence=SourceConfidence(confidence),
                            adapter_revision=ADAPTER_REVISION,
                        ),
                    ),
                )
            )
        return fields


def _normalize_hostname(value: str) -> str:
    return value.rstrip(".").casefold()


def _normalize_application(value: str) -> str:
    normalized = " ".join(value.split()).casefold()
    if not normalized:
        raise ActivityWatchMetadataFailure(ActivityWatchMetadataFailureCode.MALFORMED_RESPONSE)
    return normalized


def _scope_buckets(
    buckets: tuple[ActivityWatchBucket, ...],
    local_hostname: str,
) -> dict[
    ActivityWatchEventType,
    tuple[ActivityWatchBucket, ...],
]:
    if len(buckets) > MAX_BUCKETS:
        raise ActivityWatchAdapterFailure(ActivityWatchMetadataFailureCode.TOO_MANY_BUCKETS)

    grouped: dict[
        ActivityWatchEventType,
        list[ActivityWatchBucket],
    ] = {}
    for bucket in buckets:
        grouped.setdefault(bucket.event_type, []).append(bucket)

    scoped: dict[
        ActivityWatchEventType,
        tuple[ActivityWatchBucket, ...],
    ] = {}
    local = _normalize_hostname(local_hostname)

    for event_type, candidates in grouped.items():
        local_candidates = [
            item for item in candidates if _normalize_hostname(item.hostname) == local
        ]
        if local_candidates:
            selected = local_candidates
        else:
            by_host: dict[str, list[ActivityWatchBucket]] = {}
            for item in candidates:
                by_host.setdefault(
                    _normalize_hostname(item.hostname),
                    [],
                ).append(item)
            if len(by_host) > 1:
                raise ActivityWatchAdapterFailure(
                    ActivityWatchMetadataFailureCode.AMBIGUOUS_BUCKETS
                )
            selected = next(iter(by_host.values())) if by_host else []

        if len(selected) > MAX_CANDIDATES_PER_TYPE:
            raise ActivityWatchAdapterFailure(ActivityWatchMetadataFailureCode.AMBIGUOUS_BUCKETS)

        scoped[event_type] = tuple(
            sorted(
                selected,
                key=lambda item: (
                    -item.created_at.timestamp(),
                    item.bucket_id,
                ),
            )
        )
    return scoped


def _correlate_event(
    events: tuple[ActivityWatchEvent, ...],
    *,
    expected_type: ActivityWatchEventType,
    observed_at: datetime,
    tolerance_seconds: float,
) -> ActivityWatchEvent | None:
    unique: dict[
        tuple[
            ActivityWatchEventType,
            datetime,
            float,
            str | None,
            str | None,
            bool | None,
            str | None,
        ],
        ActivityWatchEvent,
    ] = {}

    for event in events:
        if event.event_type is not expected_type:
            continue
        key = (
            event.event_type,
            event.timestamp,
            event.duration_seconds,
            event.application,
            event.title,
            event.idle,
            event.domain,
        )
        unique[key] = event

    candidates = [
        event
        for event in unique.values()
        if _event_distance_seconds(event, observed_at) <= tolerance_seconds
        and abs((observed_at - event.timestamp).total_seconds()) <= tolerance_seconds
    ]
    if not candidates:
        return None

    return min(
        candidates,
        key=lambda event: (
            _event_distance_seconds(event, observed_at),
            -event.timestamp.timestamp(),
            event.duration_seconds,
            event.event_type.value,
        ),
    )


def _event_distance_seconds(
    event: ActivityWatchEvent,
    observed_at: datetime,
) -> float:
    start = event.timestamp
    end = start + timedelta(seconds=event.duration_seconds)
    if start <= observed_at <= end:
        return 0.0
    if end < observed_at:
        return (observed_at - end).total_seconds()
    return (start - observed_at).total_seconds()
