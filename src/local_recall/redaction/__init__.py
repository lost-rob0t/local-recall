"""Local OCR and deterministic pre-persistence redaction."""

from .codec import (
    AnalyzedCapture,
    decode_analyzed_stage,
    decode_raw_stage,
    decode_redacted_stage,
    encode_analyzed_stage,
    encode_raw_frame,
    encode_redacted_stage,
)
from .detector import DeterministicSecretDetector, shannon_entropy
from .errors import (
    LocalOCRFailure,
    OCRFailureCode,
    RedactionFailure,
    RedactionFailureCode,
)
from .models import AllowlistedMatch, DetectionResult, SecretMatch
from .policy import DeterministicRedactionPolicy
from .processors import LocalOCRStageProcessor, PrePersistenceRedactionStageProcessor
from .tesseract import (
    LocalSubprocessOCRRunner,
    OCRCommandResult,
    OCRCommandRunner,
    TesseractOCRProvider,
    encode_portable_anymap,
    parse_tesseract_tsv,
)

__all__ = [
    "AllowlistedMatch",
    "AnalyzedCapture",
    "DetectionResult",
    "DeterministicRedactionPolicy",
    "DeterministicSecretDetector",
    "LocalOCRFailure",
    "LocalOCRStageProcessor",
    "LocalSubprocessOCRRunner",
    "OCRCommandResult",
    "OCRCommandRunner",
    "OCRFailureCode",
    "PrePersistenceRedactionStageProcessor",
    "RedactionFailure",
    "RedactionFailureCode",
    "SecretMatch",
    "TesseractOCRProvider",
    "decode_analyzed_stage",
    "decode_raw_stage",
    "decode_redacted_stage",
    "encode_analyzed_stage",
    "encode_portable_anymap",
    "encode_raw_frame",
    "encode_redacted_stage",
    "parse_tesseract_tsv",
    "shannon_entropy",
]
