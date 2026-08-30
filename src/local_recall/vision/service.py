"""Vision analysis service for redacted screenshots.

The pipeline invariant is capture -> deterministic redaction -> authorized
vision provider. Requests carry only redacted frames; raw frames are rejected
at the type boundary. Local providers are the default; remote providers run
only through the egress gate with an explicit per-query image grant.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import NoReturn, Protocol

from local_recall.domain import EgressAuthorization, EgressDataClass
from local_recall.domain._validation import require_nonempty
from local_recall.domain.frames import RedactedFrame, RedactedRecord
from local_recall.domain.privacy import ProviderLocation
from local_recall.domain.providers import ModelCapability, ProviderCapabilities
from local_recall.routing import EgressGate, EgressPayload


class VisionUnavailable(RuntimeError):
    """The configured vision provider is temporarily unavailable."""


class VisionRefused(RuntimeError):
    """Vision analysis was refused by policy."""


@dataclass(frozen=True, slots=True, repr=False)
class VisionAnalysisRequest:
    """One redacted-frame analysis request; raw frames are structurally impossible."""

    record_id: object
    frame: RedactedFrame
    redaction_finding_count: int = 0

    def __post_init__(self) -> None:
        if type(self.frame) is not RedactedFrame:
            raise ValueError("vision analysis requires a redacted frame")

    def __repr__(self) -> str:
        return (
            f"VisionAnalysisRequest(record_id={self.record_id!r}, "
            f"policy_revision={self.frame.policy_revision!r}, "
            f"redaction_finding_count={self.redaction_finding_count})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class VisionAnalysis:
    """Closed schema: visible application state, document type, broad task, uncertainty."""

    record_id: object
    provider_id: str
    model_version: str
    visible_application_state: str
    document_type: str
    broad_task: str
    uncertainty: float

    def __post_init__(self) -> None:
        require_nonempty(self.provider_id, "provider_id")
        require_nonempty(self.model_version, "model_version")
        for name, value in (
            ("visible_application_state", self.visible_application_state),
            ("document_type", self.document_type),
            ("broad_task", self.broad_task),
        ):
            require_nonempty(value, name)
            if len(value) > 256:
                raise ValueError(f"{name} exceeds maximum length")
        if not 0.0 <= self.uncertainty <= 1.0:
            raise ValueError("uncertainty must be between 0 and 1")

    def __repr__(self) -> str:
        return (
            f"VisionAnalysis(record_id={self.record_id!r}, "
            f"provider_id={self.provider_id!r}, model_version={self.model_version!r}, "
            f"uncertainty={self.uncertainty!r})"
        )


class VisionProvider(Protocol):
    async def capabilities(self) -> ProviderCapabilities: ...

    async def analyze(self, request: VisionAnalysisRequest) -> VisionAnalysis: ...


class VisionEnrichmentService:
    """Enrich already-redacted records with a local-first vision model.

    Provider unavailability never blocks OCR-based capture: callers use
    enrich_optional for best-effort enrichment. Remote providers run only
    through the egress gate with an explicit per-query image grant bound to
    the exact provider.
    """

    def __init__(
        self,
        *,
        local_providers: tuple[VisionProvider, ...] = (),
        remote_providers: tuple[VisionProvider, ...] = (),
        egress_gate: EgressGate | None = None,
        max_image_bytes: int = 4_000_000,
    ) -> None:
        if not local_providers and not remote_providers:
            raise ValueError("vision enrichment requires at least one provider")
        self._local = local_providers
        self._remote = remote_providers
        self._egress_gate = egress_gate
        self._max_image_bytes = max_image_bytes

    def __repr__(self) -> str:
        return (
            "VisionEnrichmentService("
            f"local_provider_count={len(self._local)}, "
            f"remote_provider_count={len(self._remote)})"
        )

    async def enrich(
        self,
        record: RedactedRecord,
        *,
        egress_authorization: EgressAuthorization | None = None,
    ) -> VisionAnalysis:
        request = self._request(record)
        if self._local:
            return await self._analyze(self._local[0], request)
        remote = await self._require_remote(record, egress_authorization)
        return await self._analyze(remote, request, remote=True)

    async def enrich_optional(
        self,
        record: RedactedRecord,
        *,
        egress_authorization: EgressAuthorization | None = None,
    ) -> VisionAnalysis | None:
        try:
            return await self.enrich(record, egress_authorization=egress_authorization)
        except VisionUnavailable, VisionRefused:
            return None

    async def enrich_request(self, request: VisionAnalysisRequest) -> VisionAnalysis:
        if type(request.frame) is not RedactedFrame:
            raise ValueError("vision analysis requires a redacted frame")
        if not self._local:
            self._refuse("remote")
        return await self._validate(await self._local[0].analyze(request), request)

    def _request(self, record: RedactedRecord) -> VisionAnalysisRequest:
        if type(record.frame) is not RedactedFrame:
            raise ValueError("vision analysis requires a redacted frame")
        return VisionAnalysisRequest(
            record_id=record.record_id,
            frame=record.frame,
            redaction_finding_count=len(record.frame.findings),
        )

    async def _analyze(
        self,
        provider: VisionProvider,
        request: VisionAnalysisRequest,
        *,
        remote: bool = False,
    ) -> VisionAnalysis:
        capabilities = await provider.capabilities()
        if not capabilities.available:
            raise VisionUnavailable("vision provider unavailable")
        if ModelCapability.VISION not in capabilities.capabilities:
            raise VisionUnavailable("vision capability required")
        if capabilities.location is ProviderLocation.REMOTE and not remote:
            self._refuse("remote")
        image_bytes = request.frame.pixels
        if len(image_bytes) > self._max_image_bytes:
            raise VisionUnavailable("vision input exceeds budget")
        analysis = await provider.analyze(request)
        return await self._validate(analysis, request)

    async def _require_remote(
        self,
        record: RedactedRecord,
        authorization: EgressAuthorization | None,
    ) -> VisionProvider:
        if authorization is None:
            self._refuse("remote vision requires explicit authorization")
        gate = self._egress_gate
        if gate is None:
            self._refuse("remote vision requires an egress gate")
        remote = self._remote[0]
        capabilities = await remote.capabilities()
        if capabilities.provider_id != authorization.provider_id:
            self._refuse("remote provider does not match the authorization")
        if EgressDataClass.REDACTED_IMAGE not in authorization.data_classes:
            self._refuse("remote vision requires an image egress grant")
        if not capabilities.available or ModelCapability.VISION not in capabilities.capabilities:
            raise VisionUnavailable("vision provider unavailable")
        payload = EgressPayload(image=record.frame.pixels)
        gate.approve(payload, authorization)
        return remote

    async def _validate(
        self,
        analysis: VisionAnalysis,
        request: VisionAnalysisRequest,
    ) -> VisionAnalysis:
        if analysis.record_id != request.record_id:
            raise ValueError("vision analysis is not linked to the requested record")
        return analysis

    def _refuse(self, reason: str) -> NoReturn:
        raise VisionRefused(reason)
