from __future__ import annotations

from enum import StrEnum
from uuid import UUID


class OCRFailureCode(StrEnum):
    EXECUTABLE_UNAVAILABLE = "executable_unavailable"
    INPUT_TOO_LARGE = "input_too_large"
    EXECUTION_FAILED = "execution_failed"
    TIMEOUT = "timeout"
    MALFORMED_OUTPUT = "malformed_output"


class RedactionFailureCode(StrEnum):
    FRAME_MISMATCH = "frame_mismatch"
    INVALID_REGION = "invalid_region"
    DETECTION_FAILED = "detection_failed"
    CODEC_FAILURE = "codec_failure"
    POLICY_FAILURE = "policy_failure"


class LocalOCRFailure(RuntimeError):
    def __init__(self, frame_id: UUID, code: OCRFailureCode) -> None:
        self.frame_id = frame_id
        self.code = code
        super().__init__(f"local OCR failed for frame {frame_id}: {code.value}")


class RedactionFailure(RuntimeError):
    def __init__(self, record_id: UUID, code: RedactionFailureCode) -> None:
        self.record_id = record_id
        self.code = code
        super().__init__(f"redaction failed for record {record_id}: {code.value}")
