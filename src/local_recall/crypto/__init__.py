"""Authenticated record encryption and fail-closed key-provider strategies."""

from .codec import decode_encrypted_stage, encode_encrypted_stage
from .envelope import (
    ENVELOPE_ALGORITHM,
    ENVELOPE_SCHEMA_VERSION,
    EnvelopeCipher,
)
from .errors import (
    EncryptionFailure,
    EncryptionFailureCode,
    KeyProviderFailure,
    KeyProviderFailureCode,
)
from .gpg import (
    GPGCommandResult,
    GPGCommandRunner,
    GPGKeyProvider,
    SubprocessGPGRunner,
)
from .keyring import (
    KeyringBackend,
    KeyringBackendLocked,
    OSKeyringProvider,
    PythonKeyringBackend,
)
from .processor import EnvelopeEncryptionStageProcessor
from .registry import KeyProviderRegistry, KeyProviderSelection

__all__ = [
    "ENVELOPE_ALGORITHM",
    "ENVELOPE_SCHEMA_VERSION",
    "EncryptionFailure",
    "EncryptionFailureCode",
    "EnvelopeCipher",
    "EnvelopeEncryptionStageProcessor",
    "GPGCommandResult",
    "GPGCommandRunner",
    "GPGKeyProvider",
    "KeyProviderFailure",
    "KeyProviderFailureCode",
    "KeyProviderRegistry",
    "KeyProviderSelection",
    "KeyringBackend",
    "KeyringBackendLocked",
    "OSKeyringProvider",
    "PythonKeyringBackend",
    "SubprocessGPGRunner",
    "decode_encrypted_stage",
    "encode_encrypted_stage",
]
