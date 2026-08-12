from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from local_recall.config import (
    ActivityWatchSettings,
    ActivityWatchURLMode,
    MetadataSettings,
)
from local_recall.domain.capture import MetadataRequest
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.metadata import (
    ActivityWatchBucket,
    ActivityWatchEvent,
    ActivityWatchEventType,
    ActivityWatchMetadataFailure,
    ActivityWatchMetadataFailureCode,
    ActivityWatchMetadataSource,
    ActivityWatchServerInfo,
)
from local_recall.ports.metadata import MetadataSource

NOW = datetime(2026, 8, 12, 14, 30, tzinfo=UTC)


def request(*requested_fields: str) -> MetadataRequest:
    return MetadataRequest(
        job_id=uuid4(),
        generation=CaptureGeneration(1),
        deadline_monotonic_ns=time.monotonic_ns() + 10_000_000_000,
        requested_fields=frozenset(requested_fields),
    )


def bucket(
    bucket_id: str,
    event_type: ActivityWatchEventType,
    *,
    hostname: str = "local-host",
    created_at: datetime = NOW - timedelta(days=1),
) -> ActivityWatchBucket:
    return ActivityWatchBucket(
        bucket_id=bucket_id,
        event_type=event_type,
        client="synthetic-watcher",
        hostname=hostname,
        created_at=created_at,
    )


def event(
    event_type: ActivityWatchEventType,
    *,
    timestamp: datetime = NOW - timedelta(seconds=1),
    duration_seconds: float = 2.0,
    application: str | None = None,
    title: str | None = None,
    idle: bool | None = None,
    domain: str | None = None,
) -> ActivityWatchEvent:
    return ActivityWatchEvent(
        event_type=event_type,
        timestamp=timestamp,
        duration_seconds=duration_seconds,
        application=application,
        title=title,
        idle=idle,
        domain=domain,
    )


@dataclass
class SyntheticClient:
    bucket_values: tuple[ActivityWatchBucket, ...]
    events_by_bucket: dict[str, tuple[ActivityWatchEvent, ...]]
    hostname: str = "local-host"
    available: bool = True
    event_calls: list[str] = field(default_factory=lambda: list[str]())
    info_calls: int = 0
    bucket_calls: int = 0

    async def server_info(
        self,
        *,
        timeout_seconds: float,
    ) -> ActivityWatchServerInfo:
        assert timeout_seconds > 0
        self.info_calls += 1
        if not self.available:
            raise OSError("synthetic unavailable detail")
        return ActivityWatchServerInfo(hostname=self.hostname)

    async def buckets(
        self,
        *,
        timeout_seconds: float,
    ) -> tuple[ActivityWatchBucket, ...]:
        assert timeout_seconds > 0
        self.bucket_calls += 1
        return self.bucket_values

    async def events(
        self,
        bucket_id: str,
        *,
        start: datetime,
        end: datetime,
        limit: int,
        timeout_seconds: float,
    ) -> tuple[ActivityWatchEvent, ...]:
        assert timeout_seconds > 0
        assert end > start
        assert 0 < limit <= 16
        self.event_calls.append(bucket_id)
        return self.events_by_bucket.get(bucket_id, ())


def source(
    client: SyntheticClient,
    *,
    titles: bool = False,
    url_mode: ActivityWatchURLMode = ActivityWatchURLMode.DISABLED,
    correlation_window_seconds: float = 2.0,
    monotonic_ns: Callable[[], int] | None = None,
) -> ActivityWatchMetadataSource:
    settings = MetadataSettings(
        window_titles_enabled=titles,
        activitywatch=ActivityWatchSettings(
            url_mode=url_mode,
            correlation_window_seconds=correlation_window_seconds,
        ),
    )
    return ActivityWatchMetadataSource(
        settings,
        client=client,
        now=lambda: NOW,
        monotonic_ns=monotonic_ns or time.monotonic_ns,
    )


def test_source_id_and_metadata_source_conformance() -> None:
    adapter = source(SyntheticClient((), {}))

    assert adapter.source_id == "activitywatch"
    assert isinstance(adapter, MetadataSource)


def test_collects_canonical_window_afk_domain_fields() -> None:
    client = SyntheticClient(
        (
            bucket("window", ActivityWatchEventType.CURRENT_WINDOW),
            bucket("afk", ActivityWatchEventType.AFK_STATUS),
            bucket("web", ActivityWatchEventType.WEB_TAB_CURRENT),
        ),
        {
            "window": (
                event(
                    ActivityWatchEventType.CURRENT_WINDOW,
                    application="Synthetic-App",
                    title="Synthetic title",
                ),
            ),
            "afk": (event(ActivityWatchEventType.AFK_STATUS, idle=False),),
            "web": (
                event(
                    ActivityWatchEventType.WEB_TAB_CURRENT,
                    domain="example.test",
                ),
            ),
        },
    )

    metadata = asyncio.run(
        source(
            client,
            titles=True,
            url_mode=ActivityWatchURLMode.DOMAIN_ONLY,
        ).collect(request())
    )

    assert tuple(item.name for item in metadata.fields) == (
        "application",
        "idle",
        "url.domain",
        "window.title",
    )
    assert metadata.get("application") == "synthetic-app"
    assert metadata.get("idle") is False
    assert metadata.get("url.domain") == "example.test"
    assert metadata.get("window.title") == "Synthetic title"
    assert metadata.observed_at == NOW


def test_title_and_url_are_disabled_by_default() -> None:
    client = SyntheticClient(
        (
            bucket("window", ActivityWatchEventType.CURRENT_WINDOW),
            bucket("web", ActivityWatchEventType.WEB_TAB_CURRENT),
        ),
        {
            "window": (
                event(
                    ActivityWatchEventType.CURRENT_WINDOW,
                    application="app",
                    title="must-not-escape",
                ),
            ),
            "web": (
                event(
                    ActivityWatchEventType.WEB_TAB_CURRENT,
                    domain="secret.test",
                ),
            ),
        },
    )

    metadata = asyncio.run(source(client).collect(request()))

    assert metadata.get("application") == "app"
    assert metadata.get("window.title") is None
    assert metadata.get("url.domain") is None
    assert client.event_calls == ["window"]


def test_requested_fields_query_only_needed_bucket_type() -> None:
    client = SyntheticClient(
        (
            bucket("window", ActivityWatchEventType.CURRENT_WINDOW),
            bucket("afk", ActivityWatchEventType.AFK_STATUS),
            bucket("web", ActivityWatchEventType.WEB_TAB_CURRENT),
        ),
        {
            "window": (event(ActivityWatchEventType.CURRENT_WINDOW, application="app"),),
            "afk": (event(ActivityWatchEventType.AFK_STATUS, idle=True),),
            "web": (
                event(
                    ActivityWatchEventType.WEB_TAB_CURRENT,
                    domain="example.test",
                ),
            ),
        },
    )

    metadata = asyncio.run(
        source(
            client,
            titles=True,
            url_mode=ActivityWatchURLMode.DOMAIN_ONLY,
        ).collect(request("idle"))
    )

    assert tuple(item.name for item in metadata.fields) == ("idle",)
    assert client.event_calls == ["afk"]


def test_idle_duration_is_normalized_only_when_requested() -> None:
    client = SyntheticClient(
        (bucket("afk", ActivityWatchEventType.AFK_STATUS),),
        {
            "afk": (
                event(
                    ActivityWatchEventType.AFK_STATUS,
                    idle=True,
                    duration_seconds=179.5,
                ),
            ),
        },
    )

    metadata = asyncio.run(source(client).collect(request("idle", "idle.seconds")))

    assert metadata.get("idle") is True
    assert metadata.get("idle.seconds") == 179.5


def test_unrelated_requested_field_avoids_activitywatch_network_work() -> None:
    client = SyntheticClient((), {})

    metadata = asyncio.run(source(client).collect(request("workspace")))

    assert metadata.fields == ()
    assert client.info_calls == 0
    assert client.bucket_calls == 0


def test_every_field_has_stable_content_free_provenance() -> None:
    client = SyntheticClient(
        (bucket("window", ActivityWatchEventType.CURRENT_WINDOW),),
        {
            "window": (
                event(
                    ActivityWatchEventType.CURRENT_WINDOW,
                    application="synthetic-app",
                    title="Synthetic title",
                ),
            )
        },
    )

    metadata = asyncio.run(source(client, titles=True).collect(request()))

    for item in metadata.fields:
        assert len(item.provenance) == 1
        provenance = item.provenance[0]
        assert provenance.source_id == "activitywatch"
        assert provenance.observed_at == NOW
        assert provenance.adapter_revision == "activitywatch-api0-v1"
        assert 0.0 < provenance.confidence.value <= 1.0
    assert "synthetic-app" not in repr(metadata)
    assert "Synthetic title" not in repr(metadata)


def test_local_hostname_candidate_wins_without_cross_host_combination() -> None:
    client = SyntheticClient(
        (
            bucket(
                "foreign",
                ActivityWatchEventType.CURRENT_WINDOW,
                hostname="other-host",
                created_at=NOW,
            ),
            bucket(
                "local",
                ActivityWatchEventType.CURRENT_WINDOW,
                hostname="local-host",
                created_at=NOW - timedelta(days=10),
            ),
        ),
        {
            "foreign": (
                event(
                    ActivityWatchEventType.CURRENT_WINDOW,
                    application="foreign-app",
                ),
            ),
            "local": (
                event(
                    ActivityWatchEventType.CURRENT_WINDOW,
                    application="local-app",
                ),
            ),
        },
    )

    metadata = asyncio.run(source(client).collect(request()))

    assert metadata.get("application") == "local-app"
    assert client.event_calls == ["local"]


def test_several_unknown_hosts_fail_closed_without_event_queries() -> None:
    client = SyntheticClient(
        (
            bucket(
                "a",
                ActivityWatchEventType.CURRENT_WINDOW,
                hostname="host-a",
            ),
            bucket(
                "b",
                ActivityWatchEventType.CURRENT_WINDOW,
                hostname="host-b",
            ),
        ),
        {},
        hostname="different-local-host",
    )

    with pytest.raises(ActivityWatchMetadataFailure) as captured:
        asyncio.run(source(client).collect(request()))

    assert captured.value.code is ActivityWatchMetadataFailureCode.AMBIGUOUS_BUCKETS
    assert client.event_calls == []


def test_same_host_candidates_choose_fresh_correlated_event() -> None:
    client = SyntheticClient(
        (
            bucket(
                "newer-stale",
                ActivityWatchEventType.CURRENT_WINDOW,
                created_at=NOW - timedelta(days=1),
            ),
            bucket(
                "older-fresh",
                ActivityWatchEventType.CURRENT_WINDOW,
                created_at=NOW - timedelta(days=20),
            ),
        ),
        {
            "newer-stale": (
                event(
                    ActivityWatchEventType.CURRENT_WINDOW,
                    timestamp=NOW - timedelta(minutes=1),
                    duration_seconds=1,
                    application="stale",
                ),
            ),
            "older-fresh": (
                event(
                    ActivityWatchEventType.CURRENT_WINDOW,
                    application="fresh",
                ),
            ),
        },
    )

    metadata = asyncio.run(source(client).collect(request()))

    assert metadata.get("application") == "fresh"
    assert set(client.event_calls) == {"newer-stale", "older-fresh"}


@pytest.mark.parametrize(
    ("timestamp", "duration", "expected"),
    [
        (NOW, 0.0, "exact"),
        (NOW - timedelta(seconds=2), 1.5, "before"),
        (NOW + timedelta(milliseconds=500), 0.0, "after"),
    ],
)
def test_correlation_accepts_exact_overlap_and_nearby_events(
    timestamp: datetime,
    duration: float,
    expected: str,
) -> None:
    client = SyntheticClient(
        (bucket("window", ActivityWatchEventType.CURRENT_WINDOW),),
        {
            "window": (
                event(
                    ActivityWatchEventType.CURRENT_WINDOW,
                    timestamp=timestamp,
                    duration_seconds=duration,
                    application=expected,
                ),
            )
        },
    )

    metadata = asyncio.run(source(client).collect(request()))

    assert metadata.get("application") == expected


def test_stale_event_is_rejected() -> None:
    client = SyntheticClient(
        (bucket("window", ActivityWatchEventType.CURRENT_WINDOW),),
        {
            "window": (
                event(
                    ActivityWatchEventType.CURRENT_WINDOW,
                    timestamp=NOW - timedelta(seconds=30),
                    duration_seconds=1,
                    application="stale",
                ),
            )
        },
    )

    with pytest.raises(ActivityWatchMetadataFailure) as captured:
        asyncio.run(source(client).collect(request()))

    assert captured.value.code is ActivityWatchMetadataFailureCode.NO_CORRELATED_EVENT


def test_out_of_order_overlap_chooses_latest_start() -> None:
    client = SyntheticClient(
        (bucket("window", ActivityWatchEventType.CURRENT_WINDOW),),
        {
            "window": (
                event(
                    ActivityWatchEventType.CURRENT_WINDOW,
                    timestamp=NOW - timedelta(seconds=1),
                    duration_seconds=2,
                    application="newer",
                ),
                event(
                    ActivityWatchEventType.CURRENT_WINDOW,
                    timestamp=NOW - timedelta(seconds=5),
                    duration_seconds=10,
                    application="older",
                ),
            )
        },
    )

    metadata = asyncio.run(source(client).collect(request()))

    assert metadata.get("application") == "newer"


def test_semantic_duplicate_event_does_not_change_result() -> None:
    duplicate = event(
        ActivityWatchEventType.CURRENT_WINDOW,
        application="same",
    )
    client = SyntheticClient(
        (bucket("window", ActivityWatchEventType.CURRENT_WINDOW),),
        {"window": (duplicate, duplicate)},
    )

    metadata = asyncio.run(source(client).collect(request()))

    assert metadata.get("application") == "same"


def test_no_compatible_buckets_uses_fixed_failure_code() -> None:
    with pytest.raises(ActivityWatchMetadataFailure) as captured:
        asyncio.run(source(SyntheticClient((), {})).collect(request()))

    assert captured.value.code is ActivityWatchMetadataFailureCode.NO_COMPATIBLE_BUCKETS


def test_is_available_reads_only_server_and_bucket_metadata() -> None:
    client = SyntheticClient(
        (bucket("window", ActivityWatchEventType.CURRENT_WINDOW),),
        {},
    )

    assert asyncio.run(source(client).is_available()) is True
    assert client.info_calls == 1
    assert client.bucket_calls == 1
    assert client.event_calls == []


def test_unavailability_is_sanitized() -> None:
    client = SyntheticClient((), {}, available=False)
    adapter = source(client)

    assert asyncio.run(adapter.is_available()) is False
    with pytest.raises(ActivityWatchMetadataFailure) as captured:
        asyncio.run(adapter.collect(request()))

    assert captured.value.code is ActivityWatchMetadataFailureCode.UNAVAILABLE
    assert "synthetic unavailable detail" not in str(captured.value)
    assert "synthetic unavailable detail" not in repr(captured.value)


def test_capture_deadline_fails_before_network_work() -> None:
    client = SyntheticClient((), {})
    expired = MetadataRequest(
        job_id=uuid4(),
        generation=CaptureGeneration(1),
        deadline_monotonic_ns=10,
    )

    with pytest.raises(ActivityWatchMetadataFailure) as captured:
        asyncio.run(source(client, monotonic_ns=lambda: 10).collect(expired))

    assert captured.value.code is ActivityWatchMetadataFailureCode.TIMEOUT
    assert client.info_calls == 0


def test_activitywatch_configuration_defaults_are_conservative() -> None:
    settings = ActivityWatchSettings()

    assert settings.endpoint == "http://127.0.0.1:5600"
    assert settings.url_mode is ActivityWatchURLMode.DISABLED
    assert 0 < settings.correlation_window_seconds <= 5


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://192.0.2.1:5600",
        "https://127.0.0.1:5600",
        "http://user:pass@127.0.0.1:5600",  # pragma: allowlist secret
        "http://127.0.0.1:5600/api/0",
        "http://127.0.0.1:5600/?query=1",
        "http://127.0.0.1:5600/#fragment",
    ],
)
def test_configuration_rejects_non_loopback_or_non_origin(
    endpoint: str,
) -> None:
    with pytest.raises(ValidationError, match="loopback"):
        ActivityWatchSettings(endpoint=endpoint)


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://127.0.0.1:5600",
        "http://localhost:5600",
        "http://[::1]:5600",
    ],
)
def test_configuration_accepts_loopback_http_origins(
    endpoint: str,
) -> None:
    assert ActivityWatchSettings(endpoint=endpoint).endpoint == endpoint


def test_old_long_running_event_is_not_treated_as_current() -> None:
    client = SyntheticClient(
        (bucket("window", ActivityWatchEventType.CURRENT_WINDOW),),
        {
            "window": (
                event(
                    ActivityWatchEventType.CURRENT_WINDOW,
                    timestamp=NOW - timedelta(hours=1),
                    duration_seconds=7200,
                    application="old-long-event",
                ),
            )
        },
    )

    with pytest.raises(ActivityWatchMetadataFailure) as captured:
        asyncio.run(source(client).collect(request()))

    assert captured.value.code is ActivityWatchMetadataFailureCode.NO_CORRELATED_EVENT


def test_far_future_event_is_rejected() -> None:
    client = SyntheticClient(
        (bucket("window", ActivityWatchEventType.CURRENT_WINDOW),),
        {
            "window": (
                event(
                    ActivityWatchEventType.CURRENT_WINDOW,
                    timestamp=NOW + timedelta(seconds=30),
                    duration_seconds=0,
                    application="future",
                ),
            )
        },
    )

    with pytest.raises(ActivityWatchMetadataFailure) as captured:
        asyncio.run(source(client).collect(request()))

    assert captured.value.code is ActivityWatchMetadataFailureCode.NO_CORRELATED_EVENT


def test_stale_afk_event_does_not_override_fresh_window_context() -> None:
    client = SyntheticClient(
        (
            bucket("window", ActivityWatchEventType.CURRENT_WINDOW),
            bucket("afk", ActivityWatchEventType.AFK_STATUS),
        ),
        {
            "window": (event(ActivityWatchEventType.CURRENT_WINDOW, application="fresh-app"),),
            "afk": (
                event(
                    ActivityWatchEventType.AFK_STATUS,
                    timestamp=NOW - timedelta(seconds=30),
                    duration_seconds=0,
                    idle=True,
                ),
            ),
        },
    )

    metadata = asyncio.run(source(client).collect(request()))

    assert metadata.get("application") == "fresh-app"
    assert metadata.get("idle") is None


def test_conflicting_afk_events_choose_latest_start_deterministically() -> None:
    client = SyntheticClient(
        (bucket("afk", ActivityWatchEventType.AFK_STATUS),),
        {
            "afk": (
                event(
                    ActivityWatchEventType.AFK_STATUS,
                    timestamp=NOW - timedelta(milliseconds=500),
                    duration_seconds=1,
                    idle=False,
                ),
                event(
                    ActivityWatchEventType.AFK_STATUS,
                    timestamp=NOW - timedelta(seconds=1),
                    duration_seconds=2,
                    idle=True,
                ),
            )
        },
    )

    metadata = asyncio.run(source(client).collect(request("idle")))

    assert metadata.get("idle") is False


def test_probe_capabilities_respect_sensitive_field_configuration() -> None:
    client = SyntheticClient(
        (
            bucket("window", ActivityWatchEventType.CURRENT_WINDOW),
            bucket("afk", ActivityWatchEventType.AFK_STATUS),
            bucket("web", ActivityWatchEventType.WEB_TAB_CURRENT),
        ),
        {},
    )

    defaults = asyncio.run(source(client).probe_capabilities())
    enabled = asyncio.run(
        source(
            client,
            titles=True,
            url_mode=ActivityWatchURLMode.DOMAIN_ONLY,
        ).probe_capabilities()
    )

    assert defaults == frozenset({"application", "activity", "idle"})
    assert enabled == frozenset({"application", "window-title", "activity", "idle", "domain"})
