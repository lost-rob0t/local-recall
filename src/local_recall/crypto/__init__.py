"""Authenticated record encryption and fail-closed key-provider strategies."""

from .cipher import ALGORITHM, ENVELOPE_SCHEMA_VERSION, RecordCipher
from .codec import decode_envelope, encode_envelope
from .errors import (
    AuthenticationFailed,
    CryptoError,
    EnvelopeFormatError,
    KeyProviderInvalid,
    KeyProviderLocked,
    KeyProviderUnavailable,
    KeyRevoked,
    RotationError,
)
from .models import (
    DecryptedRecordPayload,
    KeyDestructionResult,
    KeyProviderHealth,
    KeyProviderSelection,
    KeyProviderState,
    RewrapResult,
    WrappingKeyProvider,
)
from .preflight import EncryptionLifecyclePreflight
from .processor import EncryptionStageProcessor
from .providers import GPGKeyProvider, InMemoryKeyProvider, LocalKeyStoreProvider, OSKeyringProvider
from .router import KeyProviderRouter

__all__ = [
    "ALGORITHM",
    "ENVELOPE_SCHEMA_VERSION",
    "AuthenticationFailed",
    "CryptoError",
    "DecryptedRecordPayload",
    "EncryptionLifecyclePreflight",
    "EncryptionStageProcessor",
    "EnvelopeFormatError",
    "GPGKeyProvider",
    "InMemoryKeyProvider",
    "KeyDestructionResult",
    "KeyProviderHealth",
    "KeyProviderInvalid",
    "KeyProviderLocked",
    "KeyProviderRouter",
    "KeyProviderSelection",
    "KeyProviderState",
    "KeyProviderUnavailable",
    "KeyRevoked",
    "LocalKeyStoreProvider",
    "OSKeyringProvider",
    "RecordCipher",
    "RewrapResult",
    "RotationError",
    "WrappingKeyProvider",
    "decode_envelope",
    "encode_envelope",
]
