from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from local_recall.config import (
    ActivityWatchSettings,
    ActivityWatchURLMode,
    MetadataSettings,
)
from local_recall.metadata import (
    ActivityWatchAdapterFailure,
    ActivityWatchEventType,
    ActivityWatchMetadataFailureCode,
    LocalActivityWatchClient,
)

NOW_TEXT = "2026-08-12T14:30:00+00:00"


@dataclass
class QueueTransport:
    responses: list[bytes]
    targets: list[str] = field(default_factory=list)
    limits: list[int] = field(default_factory=list)

    async def get(
        self,
        target: str,
        *,
        max_response_bytes: int,
        timeout_seconds: float | None = None,
    ) -> bytes:
        assert timeout_seconds is None or timeout_seconds > 0
        self.targets.append(target)
        self.limits.append(max_response_bytes)
        if not self.responses:
            raise AssertionError("unexpected synthetic transport request")
        return self.responses.pop(0)


def encoded(value: object) -> bytes:
    return json.dumps(
        value,
        separators=(",", ":"),
    ).encode()


def bucket_payload(
    event_type: str,
    *,
    bucket_id: str = "bucket",
    hostname: str = "local-host",
) -> dict[str, object]:
    return {
        bucket_id: {
            "type": event_type,
            "client": "synthetic-client",
            "hostname": hostname,
            "created": NOW_TEXT,
        }
    }


def event_payload(
    data: object,
    *,
    timestamp: str = NOW_TEXT,
    duration: object = 1.0,
) -> dict[str, object]:
    return {
        "timestamp": timestamp,
        "duration": duration,
        "data": data,
    }


def client(
    responses: list[bytes],
    *,
    titles: bool = False,
    url_mode: ActivityWatchURLMode = ActivityWatchURLMode.DISABLED,
) -> tuple[LocalActivityWatchClient, QueueTransport]:
    transport = QueueTransport(responses)
    settings = MetadataSettings(
        window_titles_enabled=titles,
        activitywatch=ActivityWatchSettings(url_mode=url_mode),
    )
    return LocalActivityWatchClient(
        settings,
        transport=transport,
    ), transport


def discover_and_events(
    adapter: LocalActivityWatchClient,
) -> tuple[object, ...]:
    asyncio.run(adapter.buckets(timeout_seconds=0.5))
    return asyncio.run(
        adapter.events(
            "bucket",
            start=datetime(2026, 8, 12, 14, 29, 58, tzinfo=UTC),
            end=datetime(2026, 8, 12, 14, 30, 2, tzinfo=UTC),
            limit=16,
            timeout_seconds=0.5,
        )
    )


def test_server_info_and_bucket_discovery_use_stable_metadata() -> None:
    adapter, transport = client(
        [
            encoded({"hostname": "local-host", "version": "synthetic"}),
            encoded(
                {
                    **bucket_payload("currentwindow", bucket_id="window"),
                    **bucket_payload("afkstatus", bucket_id="afk"),
                    **bucket_payload("web.tab.current", bucket_id="web"),
                    **bucket_payload("unknown", bucket_id="ignored"),
                    "malformed": {
                        "type": "currentwindow",
                        "client": "x",
                        "hostname": "x",
                    },
                }
            ),
        ]
    )

    info = asyncio.run(adapter.server_info(timeout_seconds=0.5))
    buckets = asyncio.run(adapter.buckets(timeout_seconds=0.5))

    assert info.hostname == "local-host"
    assert tuple(item.bucket_id for item in buckets) == (
        "window",
        "afk",
        "web",
    )
    assert tuple(item.event_type for item in buckets) == (
        ActivityWatchEventType.CURRENT_WINDOW,
        ActivityWatchEventType.AFK_STATUS,
        ActivityWatchEventType.WEB_TAB_CURRENT,
    )
    assert transport.targets == ["/api/0/info", "/api/0/buckets/"]


def test_duplicate_json_keys_fail_closed_without_value_leak() -> None:
    marker = "synthetic-secret-marker"
    payload = (
        b'{"hostname":"local-host","hostname":"'
        + marker.encode()
        + b'"}'
    )
    adapter, _ = client([payload])

    with pytest.raises(ActivityWatchAdapterFailure) as captured:
        asyncio.run(adapter.server_info(timeout_seconds=0.5))

    assert captured.value.code is ActivityWatchMetadataFailureCode.INVALID_JSON
    assert marker not in str(captured.value)
    assert marker not in repr(captured.value)


def test_wrong_top_level_json_type_fails_closed() -> None:
    adapter, _ = client([encoded([])])

    with pytest.raises(ActivityWatchAdapterFailure) as captured:
        asyncio.run(adapter.server_info(timeout_seconds=0.5))

    assert (
        captured.value.code
        is ActivityWatchMetadataFailureCode.MALFORMED_RESPONSE
    )


def test_bucket_count_is_bounded() -> None:
    payload: dict[str, object] = {}
    for index in range(33):
        payload.update(
            bucket_payload(
                "currentwindow",
                bucket_id=f"window-{index}",
            )
        )
    adapter, _ = client([encoded(payload)])

    with pytest.raises(ActivityWatchAdapterFailure) as captured:
        asyncio.run(adapter.buckets(timeout_seconds=0.5))

    assert (
        captured.value.code
        is ActivityWatchMetadataFailureCode.TOO_MANY_BUCKETS
    )


def test_window_event_parses_app_and_requested_title() -> None:
    adapter, _ = client(
        [
            encoded(bucket_payload("currentwindow")),
            encoded(
                [
                    event_payload(
                        {
                            "app": "Synthetic-App",
                            "title": "Synthetic title",
                        }
                    )
                ]
            ),
        ],
        titles=True,
    )

    events = discover_and_events(adapter)

    assert len(events) == 1
    item = events[0]
    assert getattr(item, "application") == "Synthetic-App"
    assert getattr(item, "title") == "Synthetic title"


def test_disabled_title_is_discarded_at_parse_boundary() -> None:
    marker = "synthetic-sensitive-title"
    adapter, _ = client(
        [
            encoded(bucket_payload("currentwindow")),
            encoded(
                [
                    event_payload(
                        {
                            "app": "app",
                            "title": marker,
                        }
                    )
                ]
            ),
        ]
    )

    events = discover_and_events(adapter)

    assert len(events) == 1
    assert getattr(events[0], "title") is None
    assert marker not in repr(events[0])


@pytest.mark.parametrize(
    "data",
    [
        {"app": 7, "title": "title"},
        {"app": "a" * 257, "title": "title"},
        {"app": "app", "title": "t" * 4097},
    ],
)
def test_malformed_or_excessive_window_fields_are_rejected(
    data: dict[str, object],
) -> None:
    adapter, _ = client(
        [
            encoded(bucket_payload("currentwindow")),
            encoded([event_payload(data)]),
        ],
        titles=True,
    )

    assert discover_and_events(adapter) == ()


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("afk", True),
        ("not-afk", False),
    ],
)
def test_afk_status_is_closed_typed_boolean(
    status: str,
    expected: bool,
) -> None:
    adapter, _ = client(
        [
            encoded(bucket_payload("afkstatus")),
            encoded([event_payload({"status": status})]),
        ]
    )

    events = discover_and_events(adapter)

    assert len(events) == 1
    assert getattr(events[0], "idle") is expected


def test_unknown_afk_status_is_not_forwarded() -> None:
    adapter, _ = client(
        [
            encoded(bucket_payload("afkstatus")),
            encoded([event_payload({"status": "maybe-afk"})]),
        ]
    )

    assert discover_and_events(adapter) == ()


def test_domain_only_strips_path_query_and_fragment() -> None:
    marker = "sensitive-query-token"
    adapter, _ = client(
        [
            encoded(bucket_payload("web.tab.current")),
            encoded(
                [
                    event_payload(
                        {
                            "url": (
                                "https://Example.Test/private/path?"
                                f"token={marker}#fragment"
                            )
                        }
                    )
                ]
            ),
        ],
        url_mode=ActivityWatchURLMode.DOMAIN_ONLY,
    )

    events = discover_and_events(adapter)

    assert len(events) == 1
    assert getattr(events[0], "domain") == "example.test"
    assert marker not in repr(events[0])
    assert "/private/path" not in repr(events[0])


@pytest.mark.parametrize(
    "url",
    [
        "https://user:pass@example.test/path",
        "http://127.0.0.1/private",
        "http://[::1]/private",
        "not a url",
        "https://" + "a" * 4097,
    ],
)
def test_domain_only_rejects_credential_ip_or_malformed_urls(
    url: str,
) -> None:
    adapter, _ = client(
        [
            encoded(bucket_payload("web.tab.current")),
            encoded([event_payload({"url": url})]),
        ],
        url_mode=ActivityWatchURLMode.DOMAIN_ONLY,
    )

    assert discover_and_events(adapter) == ()


def test_url_disabled_does_not_materialize_domain() -> None:
    adapter, _ = client(
        [
            encoded(bucket_payload("web.tab.current")),
            encoded(
                [
                    event_payload(
                        {"url": "https://example.test/private"}
                    )
                ]
            ),
        ]
    )

    assert discover_and_events(adapter) == ()


@pytest.mark.parametrize(
    ("timestamp", "duration"),
    [
        ("not-a-time", 1.0),
        (NOW_TEXT, -1),
        (NOW_TEXT, 86_401),
        (NOW_TEXT, "1"),
    ],
)
def test_malformed_event_time_or_duration_is_dropped(
    timestamp: str,
    duration: object,
) -> None:
    adapter, _ = client(
        [
            encoded(bucket_payload("currentwindow")),
            encoded(
                [
                    event_payload(
                        {"app": "app"},
                        timestamp=timestamp,
                        duration=duration,
                    )
                ]
            ),
        ]
    )

    assert discover_and_events(adapter) == ()


def test_event_query_is_a_tiny_bounded_range() -> None:
    adapter, transport = client(
        [
            encoded(bucket_payload("currentwindow")),
            encoded([event_payload({"app": "app"})]),
        ]
    )

    discover_and_events(adapter)

    event_target = transport.targets[-1]
    assert event_target.startswith("/api/0/buckets/bucket/events?")
    assert "limit=16" in event_target
    assert "export" not in event_target
