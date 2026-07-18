from local_recall.config import CaptureOverloadPolicy, CaptureSettings
from local_recall.pipeline import PipelineLimits, PipelineOverloadPolicy


def test_pipeline_limits_are_derived_from_validated_capture_configuration() -> None:
    settings = CaptureSettings(
        raw_queue_items=2,
        max_queue_items=7,
        overload_policy=CaptureOverloadPolicy.COALESCE_LATEST,
    )

    limits = PipelineLimits.from_capture_settings(settings)

    assert limits.raw_queue_items == 2
    assert limits.stage_queue_items == 7
    assert limits.overload_policy is PipelineOverloadPolicy.COALESCE_LATEST
