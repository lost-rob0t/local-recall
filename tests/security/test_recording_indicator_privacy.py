from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from local_recall.cli_contract import PROTOCOL_VERSION, CliOutcome, CliRequest, CliResponse
from local_recall.indicator import IndicatorController
from local_recall.indicator_views import IndicatorSurface, StatusNotifierItemAdapter

pytestmark = pytest.mark.security


@dataclass
class FailingClient:
    requests: list[CliRequest]

    def request(self, request: CliRequest) -> CliResponse:
        self.requests.append(request)
        return CliResponse(
            protocol_version=PROTOCOL_VERSION,
            request_id=request.request_id,
            outcome=CliOutcome.UNAVAILABLE,
            reason_code="TOPSECRET-window-title-ocr-provider-payload",
        )


def test_indicator_failure_surfaces_drop_daemon_reason_content() -> None:
    now = datetime(2026, 8, 22, 20, 0, tzinfo=UTC)
    client = FailingClient(requests=[])
    adapter = StatusNotifierItemAdapter(
        IndicatorSurface(IndicatorController(client=client, timeout=timedelta(seconds=2)))
    )

    presentation = adapter.poll(now=now)
    rendered = " ".join(
        (presentation.status, presentation.icon_name, presentation.title, presentation.tooltip)
    )

    assert "TOPSECRET" not in rendered
    assert "window-title" not in rendered
    assert "ocr" not in rendered.lower()
    assert "provider-payload" not in rendered


def test_indicator_modules_have_no_capture_storage_provider_or_transport_authority() -> None:
    root = Path(__file__).parents[2]
    sources = "\n".join(
        (root / path).read_text(encoding="utf-8")
        for path in (
            "src/local_recall/indicator.py",
            "src/local_recall/indicator_views.py",
        )
    )

    forbidden_imports = (
        "local_recall.capture",
        "local_recall.storage",
        "local_recall.providers",
        "local_recall.policy",
        "local_recall.lifecycle",
        "subprocess",
        "socket",
        "zmq",
    )
    for forbidden in forbidden_imports:
        assert forbidden not in sources
