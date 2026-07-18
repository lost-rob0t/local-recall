"""Backend-neutral strategy interfaces."""

from .capture import CaptureBackend
from .clock import Clock
from .encryption import DecryptionRequest, EncryptionProvider, EncryptionRequest
from .keys import (
    KeyDestructionRequest,
    KeyDestructionResult,
    KeyHealthReport,
    KeyHealthStatus,
    KeyProvider,
    KeyRotationRequest,
    KeyUnwrapRequest,
    KeyWrapRequest,
)
from .metadata import MetadataSource
from .ocr import OCRProvider, OCRRequest
from .policy import CapturePolicy
from .providers import EmbeddingProvider, GenerationProvider
from .redaction import RedactionPolicy, RedactionRequest
from .routing import ModelRoutingPolicy
from .storage import (
    CatalogRecord,
    DayRangeQuery,
    DeleteRequest,
    DeleteResult,
    QueryableStorageBackend,
    StorageBackend,
    StorageIntegrityReport,
)

__all__ = [
    "CaptureBackend",
    "CapturePolicy",
    "CatalogRecord",
    "Clock",
    "DayRangeQuery",
    "DecryptionRequest",
    "DeleteRequest",
    "DeleteResult",
    "EmbeddingProvider",
    "EncryptionProvider",
    "EncryptionRequest",
    "GenerationProvider",
    "KeyDestructionRequest",
    "KeyDestructionResult",
    "KeyHealthReport",
    "KeyHealthStatus",
    "KeyProvider",
    "KeyRotationRequest",
    "KeyUnwrapRequest",
    "KeyWrapRequest",
    "MetadataSource",
    "ModelRoutingPolicy",
    "OCRProvider",
    "OCRRequest",
    "QueryableStorageBackend",
    "RedactionPolicy",
    "RedactionRequest",
    "StorageBackend",
    "StorageIntegrityReport",
]
