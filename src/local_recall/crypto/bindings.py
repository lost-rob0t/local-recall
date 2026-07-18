from __future__ import annotations

from collections.abc import Callable
from typing import cast

from nacl import bindings

EncryptFunction = Callable[[bytes, bytes, bytes, bytes], bytes]
DecryptFunction = Callable[[bytes, bytes, bytes, bytes], bytes]

KEY_BYTES = bindings.crypto_aead_xchacha20poly1305_ietf_KEYBYTES
NONCE_BYTES = bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
TAG_BYTES = bindings.crypto_aead_xchacha20poly1305_ietf_ABYTES

encrypt = cast(EncryptFunction, bindings.crypto_aead_xchacha20poly1305_ietf_encrypt)
decrypt = cast(DecryptFunction, bindings.crypto_aead_xchacha20poly1305_ietf_decrypt)
