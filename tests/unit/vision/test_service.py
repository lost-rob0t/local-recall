from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from local_recall.domain import EgressAuthorization, EgressDataClass
from local_recall.domain.frames import PixelFormat, RawFrame, RedactedFrame, RedactedRecord
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import ContextMetadata, SourceConfidence
from local_recall.domain.privacy import PrivacyClass, ProviderLocation
from local_recall.domain.providers import ModelCapability, ProviderCapabilities
from local_recall.domain.redaction import (
    RedactionAction,
    RedactionFinding,
    RedactionKind,
    RedactionReason,
    RedactionTarget,
    TextSpan,
)
from local_recall.vision.service import (
    VisionAnalysis,
    VisionAnalysisRequest,
    VisionEnrichmentService,
    VisionRefused,
    VisionUnavailable,
)


class FakeVLM:
    def __init__(
        self,
        *,
        provider_id: str = "local-vlm",
        location: ProviderLocation = ProviderLocation.LOCAL,
        available: bool = True,
        analysis: VisionAnalysis | None = None,
    ) -> None:
        self.provider_id = provider_id
        self.location = location
        self.available = available
        self.analysis = analysis
        self.requests: list[VisionAnalysisRequest] = []

    async def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider_id=self.provider_id,
            location=self.location,
            capabilities=frozenset({ModelCapability.VISION}),
            accepted_privacy_classes=frozenset({PrivacyClass.REDACTED_IMAGE}),
            max_input_bytes=65_536,
            supports_vision=True,
            available=self.available,
        )

    async def analyze(self, request: VisionAnalysisRequest) -> VisionAnalysis:
        self.requests.append(request)
        if self.analysis is None:
            raise VisionUnavailable("vision provider unavailable")
        return self.analysis


def _redacted_record(*, findings: int = 1) -> RedactedRecord:
    captured_at = datetime(2026, 8, 22, 10, 0, tzinfo=UTC)
    finding_tuple: tuple[RedactionFinding, ...] = ()
    if findings:
        finding_tuple = (
            RedactionFinding(
                finding_id=uuid4(),
                target=RedactionTarget.OCR_TEXT,
                kind=RedactionKind.PASSWORD,
                reason=RedactionReason.DETERMINISTIC_DETECTOR,
                action=RedactionAction.REPLACE_TEXT,
                detector_id="detector",
                confidence=SourceConfidence(1.0),
                text_span=TextSpan(start=0, end=1),
            ),
        )
    frame = RedactedFrame(
        frame_id=uuid4(),
        generation=CaptureGeneration(1),
        captured_at=captured_at,
        width=2,
        height=2,
        stride=6,
        pixel_format=PixelFormat.RGB8,
        pixels=b"PIXELS",
        metadata=ContextMetadata(observed_at=captured_at, fields=()),
        ocr_text=("redacted ocr",),
        findings=finding_tuple,
        policy_revision="redaction-policy-v1",
    )
    return RedactedRecord(record_id=uuid4(), frame=frame, created_at=captured_at)


def _analysis(record: RedactedRecord, record_id=None) -> VisionAnalysis:
    return VisionAnalysis(
        record_id=record.record_id if record_id is None else record_id,
        provider_id="local-vlm",
        model_version="vision-v3",
        visible_application_state="editor with unsaved file",
        document_type="source code",
        broad_task="programming",
        uncertainty=0.2,
    )


def test_local_vlm_enriches_synthetic_redacted_record_without_network() -> None:
    record = _redacted_record()
    provider = FakeVLM(analysis=_analysis(record))
    service = VisionEnrichmentService(local_providers=(provider,))

    result = asyncio.run(service.enrich(record))

    assert result.record_id == record.record_id
    assert result.model_version == "vision-v3"
    assert result.broad_task == "programming"
    assert result.uncertainty == pytest.approx(0.2)
    assert provider.requests[0].frame is record.frame
    assert provider.requests[0].frame.policy_revision == "redaction-policy-v1"
    assert provider.requests[0].redaction_finding_count == 1
    assert provider.requests[0].frame.metadata.fields == ()


def test_unredacted_frames_cannot_reach_the_vision_provider() -> None:
    captured_at = datetime(2026, 8, 22, 10, 0, tzinfo=UTC)
    raw = RawFrame(
        frame_id=uuid4(),
        generation=CaptureGeneration(1),
        captured_at=captured_at,
        width=2,
        height=2,
        stride=6,
        pixel_format=PixelFormat.RGB8,
        pixels=b"RAWPIX",
        metadata=ContextMetadata(observed_at=captured_at, fields=()),
    )

    with pytest.raises(ValueError, match="redacted"):
        VisionAnalysisRequest(record_id=uuid4(), frame=raw)  # type: ignore[arg-type]

    record = _redacted_record()
    provider = FakeVLM(analysis=_analysis(record))
    service = VisionEnrichmentService(local_providers=(provider,))
    tampered = VisionAnalysisRequest(record_id=record.record_id, frame=record.frame)
    object.__setattr__(tampered, "frame", raw)

    with pytest.raises(ValueError, match="redacted"):
        asyncio.run(service.enrich_request(tampered))
    assert provider.requests == []


def test_analysis_output_is_schema_validated_and_linked() -> None:
    record = _redacted_record()
    other = _redacted_record()
    provider = FakeVLM(analysis=_analysis(record, record_id=other.record_id))
    service = VisionEnrichmentService(local_providers=(provider,))

    with pytest.raises(ValueError, match="record"):
        asyncio.run(
            service.enrich_request(
                VisionAnalysisRequest(record_id=record.record_id, frame=record.frame)
            )
        )

    unlinked = VisionAnalysis(
        record_id=record.record_id,
        provider_id="local-vlm",
        model_version="vision-v3",
        visible_application_state="editor",
        document_type="code",
        broad_task="programming",
        uncertainty=1.5,
    )
    provider.analysis = unlinked
    with pytest.raises(ValueError, match="uncertainty"):
        asyncio.run(
            service.enrich_request(
                VisionAnalysisRequest(record_id=record.record_id, frame=record.frame)
            )
        )


def test_provider_unavailability_does_not_block_capture() -> None:
    record = _redacted_record()
    unavailable = FakeVLM(available=False)
    service = VisionEnrichmentService(local_providers=(unavailable,))

    with pytest.raises(VisionUnavailable):
        asyncio.run(service.enrich(record))

    assert asyncio.run(service.enrich_optional(record)) is None


def test_remote_vision_is_denied_without_explicit_image_authorization() -> None:
    record = _redacted_record()
    remote = FakeVLM(provider_id="remote-vlm", location=ProviderLocation.REMOTE, analysis=_analysis(record))
    service = VisionEnrichmentService(
        local_providers=(),
        remote_providers=(remote,),
        egress_gate=None,
    )

    with pytest.raises(VisionRefused, match="remote"):
        asyncio.run(service.enrich(record, egress_authorization=None))

    weak = EgressAuthorization(
        authorization_id="auth-1",
        provider_id="remote-vlm",
        data_classes=frozenset({EgressDataClass.REDACTED_TEXT}),
        max_payload_bytes=1_000_000,
    )
    with pytest.raises(VisionRefused, match="image"):
        asyncio.run(service.enrich(record, egress_authorization=weak))
    assert remote.requests == []


def test_remote_vision_runs_only_through_the_egress_gate_with_grant() -> None:
    record = _redacted_record()
    remote = FakeVLM(provider_id="remote-vlm", location=ProviderLocation.REMOTE, analysis=_analysis(record))
    from local_recall.routing import EgressGate

    service = VisionEnrichmentService(
        local_providers=(),
        remote_providers=(remote,),
        egress_gate=EgressGate(),
    )
    grant = EgressAuthorization(
        authorization_id="auth-2",
        provider_id="remote-vlm",
        data_classes=frozenset({EgressDataClass.REDACTED_IMAGE}),
        max_payload_bytes=1_000_000,
    )

    result = asyncio.run(service.enrich(record, egress_authorization=grant))

    assert result.record_id == record.record_id
    assert len(remote.requests) == 1


def test_mismatched_remote_provider_is_refused() -> None:
    record = _redacted_record()
    remote = FakeVLM(provider_id="remote-vlm", location=ProviderLocation.REMOTE, analysis=_analysis(record))
    from local_recall.routing import EgressGate

    service = VisionEnrichmentService(
        local_providers=(),
        remote_providers=(remote,),
        egress_gate=EgressGate(),
    )
    grant = EgressAuthorization(
        authorization_id="auth-3",
        provider_id="other-vlm",
        data_classes=frozenset({EgressDataClass.REDACTED_IMAGE}),
        max_payload_bytes=1_000_000,
    )

    with pytest.raises(VisionRefused, match="provider"):
        asyncio.run(service.enrich(record, egress_authorization=grant))
