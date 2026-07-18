from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from ._validation import require_nonempty
from .privacy import PrivacyClass, ProviderLocation


class ModelCapability(StrEnum):
    GENERATION = "generation"
    EMBEDDING = "embedding"
    VISION = "vision"


@dataclass(frozen=True, slots=True)
class ProviderCapabilities:
    provider_id: str
    location: ProviderLocation
    capabilities: frozenset[ModelCapability]
    accepted_privacy_classes: frozenset[PrivacyClass]
    max_input_bytes: int
    supports_vision: bool

    def __post_init__(self) -> None:
        require_nonempty(self.provider_id, "provider_id")
        if not self.capabilities:
            raise ValueError("provider must declare at least one capability")
        if not self.accepted_privacy_classes:
            raise ValueError("provider must declare accepted privacy classes")
        if self.max_input_bytes <= 0:
            raise ValueError("max_input_bytes must be positive")
        if self.supports_vision and ModelCapability.VISION not in self.capabilities:
            raise ValueError("vision support requires the vision capability")

    def accepts(self, privacy_class: PrivacyClass) -> bool:
        return privacy_class in self.accepted_privacy_classes


@dataclass(frozen=True, slots=True, repr=False)
class EmbeddingRequest:
    inputs: tuple[str, ...] = field(repr=False)
    privacy_class: PrivacyClass
    model_hint: str | None = None

    def __post_init__(self) -> None:
        if not self.inputs or any(not item for item in self.inputs):
            raise ValueError("embedding request requires non-empty inputs")


@dataclass(frozen=True, slots=True)
class EmbeddingResponse:
    provider_id: str
    model_id: str
    vectors: tuple[tuple[float, ...], ...]

    def __post_init__(self) -> None:
        require_nonempty(self.provider_id, "provider_id")
        require_nonempty(self.model_id, "model_id")
        if not self.vectors or any(not vector for vector in self.vectors):
            raise ValueError("embedding response requires non-empty vectors")
        dimensions = {len(vector) for vector in self.vectors}
        if len(dimensions) != 1:
            raise ValueError("embedding vectors must have consistent dimensions")


@dataclass(frozen=True, slots=True, repr=False)
class GenerationRequest:
    prompt: str = field(repr=False)
    context: tuple[str, ...] = field(repr=False)
    privacy_class: PrivacyClass
    max_output_tokens: int
    model_hint: str | None = None

    def __post_init__(self) -> None:
        require_nonempty(self.prompt, "prompt")
        if self.max_output_tokens <= 0:
            raise ValueError("max_output_tokens must be positive")


@dataclass(frozen=True, slots=True, repr=False)
class GenerationResponse:
    text: str = field(repr=False)
    provider_id: str
    model_id: str
    input_tokens: int | None = None
    output_tokens: int | None = None

    def __post_init__(self) -> None:
        require_nonempty(self.provider_id, "provider_id")
        require_nonempty(self.model_id, "model_id")
        if self.input_tokens is not None and self.input_tokens < 0:
            raise ValueError("input_tokens must be non-negative")
        if self.output_tokens is not None and self.output_tokens < 0:
            raise ValueError("output_tokens must be non-negative")


@dataclass(frozen=True, slots=True)
class RoutingRequest:
    capability: ModelCapability
    privacy_class: PrivacyClass
    allow_remote: bool
    egress_authorization_id: str | None = None


@dataclass(frozen=True, slots=True)
class RoutingDecision:
    provider_id: str
    location: ProviderLocation
    capability: ModelCapability
    egress_authorization_id: str | None
    reason_code: str

    def __post_init__(self) -> None:
        require_nonempty(self.provider_id, "provider_id")
        require_nonempty(self.reason_code, "reason_code")
        if self.location is ProviderLocation.REMOTE:
            if self.egress_authorization_id is None:
                raise ValueError("remote routing requires explicit egress authorization")
            require_nonempty(self.egress_authorization_id, "egress_authorization_id")
