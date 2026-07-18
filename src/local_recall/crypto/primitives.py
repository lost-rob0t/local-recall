from __future__ import annotations

import hashlib
import hmac
import os

from nacl import bindings, exceptions

from local_recall.domain.crypto import KeyHandle

from .errors import AuthenticationFailed, EnvelopeFormatError

_WRAP_MAGIC = b"LRKW\x01"
_NONCE_BYTES = bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
_KEY_BYTES = bindings.crypto_aead_xchacha20poly1305_ietf_KEYBYTES


def random_key() -> bytearray:
    return bytearray(os.urandom(_KEY_BYTES))


def wipe(secret: bytearray) -> None:
    secret[:] = b"\x00" * len(secret)


def key_wrap_aad(record_aad_digest: bytes, handle: KeyHandle) -> bytes:
    descriptor = f"{handle.provider_id}\x00{handle.key_id}\x00{handle.version}".encode()
    return b"local-recall-key-wrap-v1\x00" + record_aad_digest + descriptor


def wrap_with_kek(kek: bytes, data_key: bytes, associated_data: bytes) -> bytes:
    if len(kek) != _KEY_BYTES or len(data_key) != _KEY_BYTES:
        raise ValueError("key material must be 32 bytes")
    nonce = os.urandom(_NONCE_BYTES)
    ciphertext = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        data_key, associated_data, nonce, kek
    )
    return _WRAP_MAGIC + nonce + ciphertext


def unwrap_with_kek(kek: bytes, wrapped: bytes, associated_data: bytes) -> bytearray:
    if len(kek) != _KEY_BYTES:
        raise ValueError("key material must be 32 bytes")
    minimum = len(_WRAP_MAGIC) + _NONCE_BYTES + _KEY_BYTES + 16
    if len(wrapped) < minimum or not hmac.compare_digest(wrapped[: len(_WRAP_MAGIC)], _WRAP_MAGIC):
        raise EnvelopeFormatError("invalid_wrapped_key")
    nonce_start = len(_WRAP_MAGIC)
    nonce_end = nonce_start + _NONCE_BYTES
    try:
        plaintext = bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            wrapped[nonce_end:], associated_data, wrapped[nonce_start:nonce_end], kek
        )
    except exceptions.CryptoError:
        raise AuthenticationFailed("wrapped_key_authentication_failed") from None
    if len(plaintext) != _KEY_BYTES:
        raise EnvelopeFormatError("invalid_unwrapped_key_length")
    return bytearray(plaintext)


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
