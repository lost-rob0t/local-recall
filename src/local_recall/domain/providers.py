from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from ._validation import require_nonempty
from .privacy import PrivacyClass, ProviderLocation


class ModelCapability(StrEnum):
    GENERATION = "generation"
    EMBEDDING = "embedding"
    VISION = "vision"


class GenerationRole(StrEnum):
    EXTRACTION = "extraction"
    SUMMARIZATION = "summarization"
    ANSWERING = "answering"


class EgressDataClass(StrEnum):
    REDACTED_TEXT = "redacted-text"
    APPROVED_METADATA = "approved-metadata"
    REDACTED_IMAGE = "redacted-image"


@dataclass(frozen=True, slots=True)
class EgressAuthorization:
    authorization_id: str
    provider_id: str
    data_classes: frozenset[EgressDataClass]
    max_payload_bytes: int

    def __post_init__(self) -> None:
        require_nonempty(self.authorization_id, "authorization_id")
        require_nonempty(self.provider_id, "provider_id")
        if not self.data_classes:
            raise ValueError("egress authorization requires data classes")
        if self.max_payload_bytes <= 0:
            raise ValueError("egress payload limit must be positive")


@dataclass(frozen=True, slots=True)
class ProviderCapabilities:
    provider_id: str
    location: ProviderLocation
    capabilities: frozenset[ModelCapability]
    accepted_privacy_classes: frozenset[PrivacyClass]
    max_input_bytes: int
    supports_vision: bool
    max_context_tokens: int | None = None
    supports_structured_output: bool = False
    available: bool = True

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
        if self.max_context_tokens is not None and self.max_context_tokens <= 0:
            raise ValueError("max_context_tokens must be positive")

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
    role: GenerationRole = GenerationRole.ANSWERING

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
        require_nonempty(self.text, "text")
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
    allow_remote: bool = False
    egress_authorization_id: str | None = None
    data_classes: frozenset[EgressDataClass] = frozenset()
    authorization: EgressAuthorization | None = None

    def __post_init__(self) -> None:
        if self.egress_authorization_id is not None:
            require_nonempty(self.egress_authorization_id, "egress_authorization_id")
        if self.authorization is not None:
            if not self.allow_remote:
                raise ValueError("egress authorization requires allow_remote")
            if self.egress_authorization_id not in {None, self.authorization.authorization_id}:
                raise ValueError("egress authorization identifiers must match")


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
        if self.location is ProviderLocation.REMOTE and self.egress_authorization_id is None:
            raise ValueError("remote routing requires explicit egress authorization")
        if self.egress_authorization_id is not None:
            require_nonempty(self.egress_authorization_id, "egress_authorization_id")
