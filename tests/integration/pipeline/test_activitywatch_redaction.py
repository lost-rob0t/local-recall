from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from local_recall.config import (
    ActivityWatchSettings,
    ActivityWatchURLMode,
    CustomRedactionPattern,
    MetadataSettings,
    RedactionSettings,
)
from local_recall.domain.capture import MetadataRequest
from local_recall.domain.frames import OCRResult
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.metadata import (
    ActivityWatchBucket,
    ActivityWatchEvent,
    ActivityWatchEventType,
    ActivityWatchMetadataSource,
    ActivityWatchServerInfo,
)
from local_recall.ports.redaction import RedactionRequest
from local_recall.redaction import DeterministicRedactionPolicy
from local_recall.session import (
    ActivityWatchMetadataProbe,
    EnvironmentSnapshot,
    GenericXorgMetadataProbe,
    ProbeOutcome,
    SessionResolver,
)

from .support import gray_frame

NOW = datetime(2026, 8, 12, 14, 30, tzinfo=UTC)


@dataclass
class SyntheticActivityWatchClient:
    available: bool = True

    async def server_info(
        self,
        *,
        timeout_seconds: float,
    ) -> ActivityWatchServerInfo:
        assert timeout_seconds > 0
        if not self.available:
            raise OSError("synthetic unavailable secret")
        return ActivityWatchServerInfo(hostname="local-host")

    async def buckets(
        self,
        *,
        timeout_seconds: float,
    ) -> tuple[ActivityWatchBucket, ...]:
        assert timeout_seconds > 0
        return (
            ActivityWatchBucket(
                bucket_id="window",
                event_type=ActivityWatchEventType.CURRENT_WINDOW,
                client="synthetic-window",
                hostname="local-host",
                created_at=NOW,
            ),
            ActivityWatchBucket(
                bucket_id="afk",
                event_type=ActivityWatchEventType.AFK_STATUS,
                client="synthetic-afk",
                hostname="local-host",
                created_at=NOW,
            ),
            ActivityWatchBucket(
                bucket_id="web",
                event_type=ActivityWatchEventType.WEB_TAB_CURRENT,
                client="synthetic-web",
                hostname="local-host",
                created_at=NOW,
            ),
        )

    async def events(
        self,
        bucket_id: str,
        *,
        start: datetime,
        end: datetime,
        limit: int,
        timeout_seconds: float,
    ) -> tuple[ActivityWatchEvent, ...]:
        assert start < NOW < end
        assert limit <= 16
        assert timeout_seconds > 0
        if bucket_id == "window":
            return (
                ActivityWatchEvent(
                    event_type=ActivityWatchEventType.CURRENT_WINDOW,
                    timestamp=NOW,
                    duration_seconds=0,
                    application="password=synthetic-passphrase",
                    title="person@example.test",
                ),
            )
        if bucket_id == "afk":
            return (
                ActivityWatchEvent(
                    event_type=ActivityWatchEventType.AFK_STATUS,
                    timestamp=NOW,
                    duration_seconds=0,
                    idle=False,
                ),
            )
        if bucket_id == "web":
            return (
                ActivityWatchEvent(
                    event_type=ActivityWatchEventType.WEB_TAB_CURRENT,
                    timestamp=NOW,
                    duration_seconds=0,
                    domain="sensitive.example",
                ),
            )
        return ()


def request() -> MetadataRequest:
    return MetadataRequest(
        job_id=uuid4(),
        generation=CaptureGeneration(1),
        deadline_monotonic_ns=time.monotonic_ns() + 10_000_000_000,
    )


def test_activitywatch_metadata_crosses_authoritative_redaction_boundary() -> None:
    source = ActivityWatchMetadataSource(
        MetadataSettings(
            window_titles_enabled=True,
            activitywatch=ActivityWatchSettings(url_mode=ActivityWatchURLMode.DOMAIN_ONLY),
        ),
        client=SyntheticActivityWatchClient(),
        now=lambda: NOW,
    )

    context = asyncio.run(source.collect(request()))
    policy = DeterministicRedactionPolicy(
        RedactionSettings(
            custom_patterns=(
                CustomRedactionPattern(
                    pattern_id="synthetic-domain",
                    pattern=r"sensitive\.example",
                ),
            )
        ),
        now=lambda: NOW,
    )
    frame = gray_frame(
        width=1,
        height=1,
        pixels=b"\x00",
        context=context,
    )
    redacted = asyncio.run(
        policy.redact(
            RedactionRequest(
                frame=frame,
                ocr=OCRResult(frame_id=frame.frame_id, blocks=()),
                policy_revision=policy.revision,
            )
        )
    )

    metadata = redacted.frame.metadata
    assert metadata.get("application") is None
    assert metadata.get("window.title") is None
    assert metadata.get("url.domain") is None
    assert metadata.get("idle") is False
    idle = next(item for item in metadata.fields if item.name == "idle")
    assert idle.provenance[0].source_id == "activitywatch"


def test_disabled_sensitive_fields_never_reach_downstream_context() -> None:
    source = ActivityWatchMetadataSource(
        MetadataSettings(),
        client=SyntheticActivityWatchClient(),
        now=lambda: NOW,
    )

    context = asyncio.run(source.collect(request()))

    assert context.get("window.title") is None
    assert context.get("url.domain") is None


def test_activitywatch_unavailable_preserves_generic_xorg_fallback() -> None:
    async def unavailable() -> bool:
        return False

    resolver = SessionResolver(
        [ActivityWatchMetadataProbe(unavailable)],
        generic_xorg_probe=GenericXorgMetadataProbe(),
    )
    environment = EnvironmentSnapshot.from_mapping(
        {
            "XDG_SESSION_TYPE": "x11",
            "DISPLAY": ":0",
        }
    )

    result = asyncio.run(resolver.resolve(environment, ("activitywatch",)))

    assert result.recording_supported is True
    assert result.selected_metadata_sources == ("xorg-generic",)
    assert tuple(item.outcome for item in result.probe_results) == (
        ProbeOutcome.UNAVAILABLE,
        ProbeOutcome.HEALTHY,
    )
