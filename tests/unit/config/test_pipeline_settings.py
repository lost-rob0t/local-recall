import pytest
from pydantic import ValidationError

from local_recall.config import CaptureOverloadPolicy, CaptureSettings


def test_capture_pipeline_settings_are_bounded_and_default_to_drop_newest() -> None:
    settings = CaptureSettings()

    assert settings.raw_queue_items == 1
    assert settings.max_queue_items == 32
    assert settings.overload_policy is CaptureOverloadPolicy.DROP_NEWEST


def test_capture_pipeline_settings_accept_coalescing() -> None:
    settings = CaptureSettings(
        raw_queue_items=2,
        max_queue_items=8,
        overload_policy=CaptureOverloadPolicy.COALESCE_LATEST,
    )

    assert settings.raw_queue_items == 2
    assert settings.max_queue_items == 8


def test_capture_pipeline_queue_bounds_are_validated() -> None:
    with pytest.raises(ValidationError):
        CaptureSettings(raw_queue_items=0)

    with pytest.raises(ValidationError):
        CaptureSettings(max_queue_items=257)
