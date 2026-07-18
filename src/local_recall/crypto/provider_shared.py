from __future__ import annotations

import base64

from nacl import bindings

from local_recall.domain.crypto import KeyHandle, KeyRequest

from .errors import KeyProviderInvalid
from .primitives import wipe

KEY_BYTES = bindings.crypto_aead_xchacha20poly1305_ietf_KEYBYTES
NONCE_BYTES = bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES


def require_reference(request: KeyRequest) -> str:
    if request.reference is None or not request.reference.strip():
        raise KeyProviderInvalid("key_reference_missing")
    return request.reference


def require_provider(key: KeyHandle, provider_id: str) -> None:
    if key.provider_id != provider_id:
        raise KeyProviderInvalid("key_provider_mismatch")


def encode_key(material: bytearray) -> str:
    try:
        return base64.urlsafe_b64encode(bytes(material)).decode("ascii")
    finally:
        wipe(material)


def decode_key(value: str) -> bytearray:
    try:
        decoded = base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
    except Exception:
        raise KeyProviderInvalid("key_material_invalid") from None
    if len(decoded) != KEY_BYTES:
        raise KeyProviderInvalid("key_material_invalid")
    return bytearray(decoded)


def encode_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def decode_bytes(value: str, *, expected: int | None = None) -> bytes:
    try:
        decoded = base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
    except Exception:
        raise KeyProviderInvalid("base64_invalid") from None
    if expected is not None and len(decoded) != expected:
        raise KeyProviderInvalid("encoded_length_invalid")
    return decoded
