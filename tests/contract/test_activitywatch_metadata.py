from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from local_recall.config import MetadataSettings
from local_recall.domain.capture import MetadataRequest
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.metadata import ActivityWatchMetadataSource, LocalActivityWatchClient
from local_recall.ports.metadata import MetadataSource

from .suites import MetadataSourceContract

NOW = datetime(2026, 8, 12, 14, 30, tzinfo=UTC)


@dataclass
class SyntheticActivityWatchTransport:
    async def get(
        self,
        target: str,
        *,
        max_response_bytes: int,
        timeout_seconds: float | None = None,
    ) -> bytes:
        assert max_response_bytes > 0
        assert timeout_seconds is None or timeout_seconds > 0
        if target == "/api/0/info":
            return _json({"hostname": "local-host"})
        if target == "/api/0/buckets/":
            return _json(
                {
                    "window": {
                        "type": "currentwindow",
                        "client": "synthetic-window",
                        "hostname": "local-host",
                        "created": NOW.isoformat(),
                    },
                    "afk": {
                        "type": "afkstatus",
                        "client": "synthetic-afk",
                        "hostname": "local-host",
                        "created": NOW.isoformat(),
                    },
                }
            )
        if target.startswith("/api/0/buckets/window/events?"):
            return _json(
                [
                    {
                        "timestamp": NOW.isoformat(),
                        "duration": 0,
                        "data": {"app": "Synthetic-App"},
                    }
                ]
            )
        if target.startswith("/api/0/buckets/afk/events?"):
            return _json(
                [
                    {
                        "timestamp": NOW.isoformat(),
                        "duration": 0,
                        "data": {"status": "not-afk"},
                    }
                ]
            )
        raise AssertionError("unexpected ActivityWatch API target")


class TestActivityWatchMetadataContract(MetadataSourceContract):
    def make_metadata_source(self) -> MetadataSource:
        settings = MetadataSettings()
        client = LocalActivityWatchClient(
            settings,
            transport=SyntheticActivityWatchTransport(),
        )
        return ActivityWatchMetadataSource(
            settings,
            client=client,
            now=lambda: NOW,
        )

    def make_metadata_request(self) -> MetadataRequest:
        return MetadataRequest(
            job_id=uuid4(),
            generation=CaptureGeneration(1),
            deadline_monotonic_ns=time.monotonic_ns() + 10_000_000_000,
        )


def _json(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()
