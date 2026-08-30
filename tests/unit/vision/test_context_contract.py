from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from local_recall.vision.context import (
    PROTOCOL_VERSION,
    ExplainVisualContextRequest,
    ExplainVisualContextResponse,
    RemoteAuthorizationMode,
    VisualContextOutcome,
    VisualContextSelector,
)

_NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
_REQUEST_ID = "c0ffee00-0000-4000-8000-00000000aa01"


def _request(**overrides: object) -> ExplainVisualContextRequest:
    base: dict[str, object] = {
        "selector": VisualContextSelector.RECENT,
        "deadline": _NOW + timedelta(seconds=5),
    }
    base.update(overrides)
    return ExplainVisualContextRequest(request_id=_REQUEST_ID, **base)  # type: ignore[arg-type]


def test_protocol_version_is_pinned() -> None:
    assert PROTOCOL_VERSION == "zara-visual-context-v1"
    request = _request(protocol_version=PROTOCOL_VERSION)
    assert request.protocol_version == "zara-visual-context-v1"


def test_unsupported_protocol_version_is_rejected() -> None:
    with pytest.raises(ValueError):
        _request(protocol_version="zara-visual-context-v9")


def test_bounded_window_requires_both_bounds() -> None:
    with pytest.raises(ValueError):
        _request(
            protocol_version=PROTOCOL_VERSION,
            selector=VisualContextSelector.BOUNDED_WINDOW,
            start=_NOW - timedelta(hours=1),
        )
    with pytest.raises(ValueError):
        _request(
            protocol_version=PROTOCOL_VERSION,
            selector=VisualContextSelector.BOUNDED_WINDOW,
            end=_NOW,
        )
    request = _request(
        protocol_version=PROTOCOL_VERSION,
        selector=VisualContextSelector.BOUNDED_WINDOW,
        start=_NOW - timedelta(hours=1),
        end=_NOW,
    )
    assert request.selector is VisualContextSelector.BOUNDED_WINDOW


def test_bounded_window_requires_start_before_end() -> None:
    with pytest.raises(ValueError):
        _request(
            protocol_version=PROTOCOL_VERSION,
            selector=VisualContextSelector.BOUNDED_WINDOW,
            start=_NOW,
            end=_NOW - timedelta(hours=1),
        )


def test_current_and_recent_reject_bounds() -> None:
    with pytest.raises(ValueError):
        _request(
            protocol_version=PROTOCOL_VERSION,
            selector=VisualContextSelector.CURRENT,
            start=_NOW - timedelta(hours=1),
            end=_NOW,
        )


def test_maximum_records_is_bounded() -> None:
    with pytest.raises(ValueError):
        _request(protocol_version=PROTOCOL_VERSION, maximum_records=0)
    with pytest.raises(ValueError):
        _request(protocol_version=PROTOCOL_VERSION, maximum_records=9)
    assert _request(protocol_version=PROTOCOL_VERSION, maximum_records=8).maximum_records == 8


def test_naive_deadline_is_rejected() -> None:
    with pytest.raises(ValueError):
        _request(protocol_version=PROTOCOL_VERSION, deadline=datetime(2026, 8, 30, 13, 0))


def test_remote_authorization_modes() -> None:
    assert (
        _request(
            protocol_version=PROTOCOL_VERSION, remote_authorization=RemoteAuthorizationMode.EXPLICIT
        ).remote_authorization
        is RemoteAuthorizationMode.EXPLICIT
    )
    default = _request(protocol_version=PROTOCOL_VERSION)
    assert default.remote_authorization is RemoteAuthorizationMode.ABSENT


def test_request_repr_is_content_free() -> None:
    request = _request(protocol_version=PROTOCOL_VERSION)
    assert "selector" not in repr(request)
    assert "token" not in repr(request)


def test_response_outcomes_are_closed() -> None:
    assert {item.value for item in VisualContextOutcome} == {
        "explained",
        "denied",
        "unavailable",
    }


def test_response_repr_hides_explanation() -> None:
    response = ExplainVisualContextResponse(
        request_id=_REQUEST_ID,
        outcome=VisualContextOutcome.EXPLAINED,
        explanation="You were editing the roadmap document.",
        selected_start=_NOW - timedelta(minutes=5),
        selected_end=_NOW,
        record_count=2,
        provider_class="local",
        confidence_summary=0.8,
    )
    rendered = repr(response)
    assert "roadmap" not in rendered
    assert response.explanation is not None


def test_response_rejects_explained_without_text() -> None:
    with pytest.raises(ValueError):
        ExplainVisualContextResponse(
            request_id=_REQUEST_ID,
            outcome=VisualContextOutcome.EXPLAINED,
            explanation=None,
            selected_start=_NOW,
            selected_end=_NOW,
            record_count=1,
            provider_class="local",
            confidence_summary=0.5,
        )


def test_response_rejects_denied_with_content() -> None:
    with pytest.raises(ValueError):
        ExplainVisualContextResponse(
            request_id=_REQUEST_ID,
            outcome=VisualContextOutcome.DENIED,
            explanation="secret text",
            selected_start=None,
            selected_end=None,
            record_count=0,
            provider_class=None,
            confidence_summary=None,
            reason_code="privacy-mode",
        )


def test_provider_class_is_closed() -> None:
    with pytest.raises(ValueError):
        ExplainVisualContextResponse(
            request_id=_REQUEST_ID,
            outcome=VisualContextOutcome.EXPLAINED,
            explanation="text",
            selected_start=_NOW,
            selected_end=_NOW,
            record_count=1,
            provider_class="gpt",
            confidence_summary=0.5,
        )
