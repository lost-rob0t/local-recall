from __future__ import annotations

import hmac
import json
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID

from nacl import bindings, exceptions

from local_recall.config.models import EncryptionSettings
from local_recall.domain.crypto import EncryptedRecordEnvelope, KeyPurpose, KeyRequest
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.pipeline.models import RedactedStageItem

from .errors import AuthenticationFailed, EnvelopeFormatError, RotationError
from .models import DecryptedRecordPayload, RewrapResult
from .primitives import digest, key_wrap_aad, random_key, wipe
from .router import KeyProviderRouter

ENVELOPE_SCHEMA_VERSION = 2
ALGORITHM = "xchacha20-poly1305"
PAYLOAD_FORMAT = "frames-v1"
_MAX_FRAMES = 64
_MAX_PAYLOAD_BYTES = 256 * 1024 * 1024
_NONCE_BYTES = bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES


class RecordCipher:
    def __init__(
        self,
        router: KeyProviderRouter,
        settings: EncryptionSettings,
    ) -> None:
        self._router = router
        self._settings = settings
        if settings.algorithm != ALGORITHM:
            raise ValueError("unsupported encryption algorithm")

    def encrypt(self, item: RedactedStageItem) -> EncryptedRecordEnvelope:
        created_at = datetime.now(UTC)
        associated_data = _associated_data(
            record_id=str(item.record_id),
            generation=item.generation.value,
            configuration_revision=item.configuration_revision,
            created_at=created_at,
            frame_sizes=tuple(len(frame) for frame in item.frames),
        )
        associated_data_digest = digest(associated_data)
        selection = self._router.select_for_encryption(
            self._settings,
            KeyRequest(
                purpose=KeyPurpose.RECORD,
                create_if_missing=True,
                reference=(
                    self._settings.key_reference.reference
                    if self._settings.key_reference is not None
                    else None
                ),
            ),
        )
        data_key = random_key()
        nonce = os.urandom(_NONCE_BYTES)
        try:
            plaintext = b"".join(item.frames)
            ciphertext = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
                plaintext,
                associated_data,
                nonce,
                bytes(data_key),
            )
            wrapped = selection.provider.wrap_data_key(
                selection.key,
                bytes(data_key),
                key_wrap_aad(associated_data_digest, selection.key),
            )
        finally:
            wipe(data_key)
        return EncryptedRecordEnvelope(
            record_id=item.record_id,
            schema_version=ENVELOPE_SCHEMA_VERSION,
            algorithm=ALGORITHM,
            key=selection.key,
            wrapped_data_key=wrapped,
            nonce=nonce,
            ciphertext=ciphertext,
            associated_data_digest=associated_data_digest,
            created_at=created_at,
            associated_data=associated_data,
        )

    def decrypt(self, envelope: EncryptedRecordEnvelope) -> DecryptedRecordPayload:
        metadata = _validate_envelope(envelope)
        provider = self._router.provider_for_handle(envelope.key)
        data_key = provider.unwrap_data_key(
            envelope.key,
            envelope.wrapped_data_key,
            key_wrap_aad(envelope.associated_data_digest, envelope.key),
        )
        try:
            try:
                plaintext = bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
                    envelope.ciphertext,
                    envelope.associated_data,
                    envelope.nonce,
                    bytes(data_key),
                )
            except exceptions.CryptoError:
                raise AuthenticationFailed(
                    "record_authentication_failed", record_id=envelope.record_id
                ) from None
        finally:
            wipe(data_key)
        frames = _split_frames(plaintext, metadata.frame_sizes, envelope.record_id)
        return DecryptedRecordPayload(
            record_id=envelope.record_id,
            generation=CaptureGeneration(metadata.generation),
            configuration_revision=metadata.configuration_revision,
            created_at=envelope.created_at,
            frames=frames,
        )

    def rewrap(
        self,
        envelope: EncryptedRecordEnvelope,
        target_settings: EncryptionSettings,
    ) -> RewrapResult:
        _validate_envelope(envelope)
        source = self._router.provider_for_handle(envelope.key)
        data_key = source.unwrap_data_key(
            envelope.key,
            envelope.wrapped_data_key,
            key_wrap_aad(envelope.associated_data_digest, envelope.key),
        )
        try:
            target = self._router.select_for_encryption(
                target_settings,
                KeyRequest(
                    purpose=KeyPurpose.RECORD,
                    create_if_missing=True,
                    reference=(
                        target_settings.key_reference.reference
                        if target_settings.key_reference is not None
                        else None
                    ),
                ),
            )
            if target.key == envelope.key:
                return RewrapResult(envelope=envelope, changed=False, used_fallback=False)
            wrapped = target.provider.wrap_data_key(
                target.key,
                bytes(data_key),
                key_wrap_aad(envelope.associated_data_digest, target.key),
            )
        except Exception as exc:
            if isinstance(exc, RotationError):
                raise
            raise RotationError("record_rewrap_failed", record_id=envelope.record_id) from exc
        finally:
            wipe(data_key)
        return RewrapResult(
            envelope=EncryptedRecordEnvelope(
                record_id=envelope.record_id,
                schema_version=envelope.schema_version,
                algorithm=envelope.algorithm,
                key=target.key,
                wrapped_data_key=wrapped,
                nonce=envelope.nonce,
                ciphertext=envelope.ciphertext,
                associated_data_digest=envelope.associated_data_digest,
                created_at=envelope.created_at,
                associated_data=envelope.associated_data,
            ),
            changed=True,
            used_fallback=target.used_fallback,
        )


class _EnvelopeMetadata:
    def __init__(
        self,
        *,
        generation: int,
        configuration_revision: str,
        frame_sizes: tuple[int, ...],
    ) -> None:
        self.generation = generation
        self.configuration_revision = configuration_revision
        self.frame_sizes = frame_sizes


def _associated_data(
    *,
    record_id: str,
    generation: int,
    configuration_revision: str,
    created_at: datetime,
    frame_sizes: tuple[int, ...],
) -> bytes:
    if not 1 <= len(frame_sizes) <= _MAX_FRAMES:
        raise EnvelopeFormatError("invalid_frame_count")
    if any(size < 0 for size in frame_sizes) or sum(frame_sizes) > _MAX_PAYLOAD_BYTES:
        raise EnvelopeFormatError("invalid_frame_sizes")
    document = {
        "algorithm": ALGORITHM,
        "configuration_revision": configuration_revision,
        "created_at": created_at.isoformat(),
        "frame_sizes": list(frame_sizes),
        "generation": generation,
        "payload_format": PAYLOAD_FORMAT,
        "record_id": record_id,
        "schema_version": ENVELOPE_SCHEMA_VERSION,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _validate_envelope(envelope: EncryptedRecordEnvelope) -> _EnvelopeMetadata:
    if envelope.schema_version != ENVELOPE_SCHEMA_VERSION:
        raise EnvelopeFormatError("unsupported_envelope_schema", record_id=envelope.record_id)
    if envelope.algorithm != ALGORITHM:
        raise EnvelopeFormatError("unsupported_algorithm", record_id=envelope.record_id)
    if len(envelope.nonce) != _NONCE_BYTES:
        raise EnvelopeFormatError("invalid_nonce", record_id=envelope.record_id)
    if not hmac.compare_digest(digest(envelope.associated_data), envelope.associated_data_digest):
        raise AuthenticationFailed("associated_data_digest_mismatch", record_id=envelope.record_id)
    try:
        parsed = json.loads(envelope.associated_data)
    except Exception:
        raise EnvelopeFormatError("associated_data_invalid", record_id=envelope.record_id) from None
    if not isinstance(parsed, dict):
        raise EnvelopeFormatError("associated_data_invalid", record_id=envelope.record_id)
    document = cast(Mapping[str, Any], parsed)
    expected_keys = {
        "algorithm",
        "configuration_revision",
        "created_at",
        "frame_sizes",
        "generation",
        "payload_format",
        "record_id",
        "schema_version",
    }
    if set(document) != expected_keys:
        raise EnvelopeFormatError("associated_data_fields_invalid", record_id=envelope.record_id)
    if document["record_id"] != str(envelope.record_id):
        raise AuthenticationFailed("record_id_mismatch", record_id=envelope.record_id)
    if document["algorithm"] != envelope.algorithm:
        raise AuthenticationFailed("algorithm_mismatch", record_id=envelope.record_id)
    if document["schema_version"] != envelope.schema_version:
        raise AuthenticationFailed("schema_version_mismatch", record_id=envelope.record_id)
    if document["payload_format"] != PAYLOAD_FORMAT:
        raise EnvelopeFormatError("payload_format_invalid", record_id=envelope.record_id)
    if document["created_at"] != envelope.created_at.isoformat():
        raise AuthenticationFailed("created_at_mismatch", record_id=envelope.record_id)
    generation = document["generation"]
    revision = document["configuration_revision"]
    raw_sizes_object: object = document["frame_sizes"]
    if not isinstance(generation, int) or generation <= 0:
        raise EnvelopeFormatError("generation_invalid", record_id=envelope.record_id)
    if not isinstance(revision, str) or not revision:
        raise EnvelopeFormatError("configuration_revision_invalid", record_id=envelope.record_id)
    if not isinstance(raw_sizes_object, list):
        raise EnvelopeFormatError("frame_sizes_invalid", record_id=envelope.record_id)
    raw_sizes = cast(list[object], raw_sizes_object)
    if not 1 <= len(raw_sizes) <= _MAX_FRAMES:
        raise EnvelopeFormatError("frame_sizes_invalid", record_id=envelope.record_id)
    if any(not isinstance(size, int) or size < 0 for size in raw_sizes):
        raise EnvelopeFormatError("frame_sizes_invalid", record_id=envelope.record_id)
    sizes = tuple(cast(int, size) for size in raw_sizes)
    if sum(sizes) > _MAX_PAYLOAD_BYTES:
        raise EnvelopeFormatError("payload_too_large", record_id=envelope.record_id)
    return _EnvelopeMetadata(
        generation=generation,
        configuration_revision=revision,
        frame_sizes=sizes,
    )


def _split_frames(
    plaintext: bytes,
    sizes: tuple[int, ...],
    record_id: UUID,
) -> tuple[bytes, ...]:
    if sum(sizes) != len(plaintext):
        raise EnvelopeFormatError("plaintext_length_mismatch", record_id=record_id)
    frames: list[bytes] = []
    offset = 0
    for size in sizes:
        frames.append(plaintext[offset : offset + size])
        offset += size
    return tuple(frames)
