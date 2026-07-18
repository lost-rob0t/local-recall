from __future__ import annotations

from typing import get_args, get_type_hints

from local_recall.domain.capture import ApprovedCaptureRequest
from local_recall.domain.crypto import EncryptedRecordEnvelope
from local_recall.domain.frames import RawFrame, RedactedRecord
from local_recall.ports.capture import CaptureBackend
from local_recall.ports.encryption import EncryptionProvider
from local_recall.ports.storage import StorageBackend


def test_capture_backend_only_accepts_approved_requests() -> None:
    hints = get_type_hints(CaptureBackend.capture)

    assert hints["request"] is ApprovedCaptureRequest
    assert hints["return"] is RawFrame


def test_storage_backend_only_accepts_encrypted_envelopes() -> None:
    hints = get_type_hints(StorageBackend.put)

    assert hints["envelope"] is EncryptedRecordEnvelope


def test_encryption_provider_only_accepts_redacted_records() -> None:
    hints = get_type_hints(EncryptionProvider.encrypt)
    request_type = hints["request"]

    assert get_args(request_type) == (RedactedRecord,)
