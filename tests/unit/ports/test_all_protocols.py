from datetime import UTC, datetime

from local_recall.domain.capture import CaptureDecision, CapturePolicyInput, MetadataRequest
from local_recall.domain.crypto import KeyHandle, KeyRequest
from local_recall.domain.frames import OCRResult, RedactedRecord
from local_recall.domain.metadata import ContextMetadata
from local_recall.domain.providers import ProviderCapabilities, RoutingDecision, RoutingRequest
from local_recall.ports.clock import Clock
from local_recall.ports.keys import (
    KeyDestructionRequest,
    KeyDestructionResult,
    KeyProvider,
    KeyRotationRequest,
)
from local_recall.ports.metadata import MetadataSource
from local_recall.ports.ocr import OCRProvider, OCRRequest
from local_recall.ports.policy import CapturePolicy
from local_recall.ports.redaction import RedactionPolicy, RedactionRequest
from local_recall.ports.routing import ModelRoutingPolicy


class SyntheticClock:
    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic_ns(self) -> int:
        return 1


def test_clock_protocol_is_runtime_checkable() -> None:
    assert isinstance(SyntheticClock(), Clock)


def test_required_protocol_names_are_importable() -> None:
    required = (
        MetadataSource,
        CapturePolicy,
        RedactionPolicy,
        KeyProvider,
        OCRProvider,
        ModelRoutingPolicy,
    )

    assert all(item.__name__ for item in required)


def test_protocol_annotations_resolve() -> None:
    annotations = (
        MetadataRequest,
        ContextMetadata,
        CapturePolicyInput,
        CaptureDecision,
        RedactionRequest,
        RedactedRecord,
        KeyRequest,
        KeyHandle,
        KeyRotationRequest,
        KeyDestructionRequest,
        KeyDestructionResult,
        OCRRequest,
        OCRResult,
        RoutingRequest,
        ProviderCapabilities,
        RoutingDecision,
    )

    assert all(annotation is not None for annotation in annotations)
