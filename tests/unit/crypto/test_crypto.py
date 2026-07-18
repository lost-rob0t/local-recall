from __future__ import annotations

import os
import threading
from dataclasses import dataclass, replace
from pathlib import Path
from uuid import uuid4

import pytest
from keyring import errors as keyring_errors

from local_recall.config.models import CredentialReference, EncryptionSettings
from local_recall.crypto import (
    AuthenticationFailed,
    EncryptionStageProcessor,
    EnvelopeFormatError,
    GPGKeyProvider,
    InMemoryKeyProvider,
    KeyProviderLocked,
    KeyProviderRouter,
    KeyProviderUnavailable,
    KeyRevoked,
    LocalKeyStoreProvider,
    OSKeyringProvider,
    RecordCipher,
    decode_envelope,
    encode_envelope,
)
from local_recall.crypto.models import KeyProviderHealth, KeyProviderState
from local_recall.domain.crypto import KeyPurpose, KeyRequest
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.pipeline.cancellation import PipelineCancellationToken
from local_recall.pipeline.models import RedactedStageItem


def settings(provider: str = "memory", reference: str = "records") -> EncryptionSettings:
    return EncryptionSettings(
        provider_id=provider,
        key_reference=CredentialReference(provider_id=provider, reference=reference),
    )


def item() -> RedactedStageItem:
    return RedactedStageItem(
        record_id=uuid4(),
        generation=CaptureGeneration(7),
        configuration_revision="config-revision-1",
        deadline_monotonic_ns=10**18,
        frames=(b"redacted pixels", b"redacted OCR", b"sanitized metadata"),
    )


def cipher(provider: InMemoryKeyProvider | None = None) -> tuple[RecordCipher, InMemoryKeyProvider]:
    selected = provider or InMemoryKeyProvider()
    return RecordCipher(KeyProviderRouter((selected,)), settings()), selected


def test_record_round_trip_and_repr_hides_material() -> None:
    record_cipher, _ = cipher()
    source = item()

    envelope = record_cipher.encrypt(source)
    decrypted = record_cipher.decrypt(envelope)

    assert decrypted.record_id == source.record_id
    assert decrypted.generation == source.generation
    assert decrypted.configuration_revision == source.configuration_revision
    assert decrypted.frames == source.frames
    rendered = repr(envelope)
    for secret in (*source.frames, envelope.ciphertext, envelope.wrapped_data_key):
        assert secret.decode(errors="ignore") not in rendered


@pytest.mark.parametrize("field", ["ciphertext", "nonce", "associated_data", "wrapped_data_key"])
def test_tampering_fails_cleanly(field: str) -> None:
    record_cipher, _ = cipher()
    envelope = record_cipher.encrypt(item())
    value = getattr(envelope, field)
    tampered = bytes([value[0] ^ 1]) + value[1:]

    with pytest.raises((AuthenticationFailed, EnvelopeFormatError)) as captured:
        record_cipher.decrypt(replace(envelope, **{field: tampered}))

    assert "redacted" not in str(captured.value)


def test_wrong_provider_key_fails_authentication() -> None:
    record_cipher, _ = cipher()
    envelope = record_cipher.encrypt(item())
    other = InMemoryKeyProvider()
    other.active_key(KeyRequest(KeyPurpose.RECORD, True, "records"))
    wrong_cipher = RecordCipher(KeyProviderRouter((other,)), settings())

    with pytest.raises(AuthenticationFailed):
        wrong_cipher.decrypt(envelope)


def test_codec_round_trip_and_strict_lengths() -> None:
    record_cipher, _ = cipher()
    envelope = record_cipher.encrypt(item())
    encoded = encode_envelope(envelope)

    assert decode_envelope(encoded) == envelope
    with pytest.raises(EnvelopeFormatError):
        decode_envelope(encoded[:-1])
    with pytest.raises(EnvelopeFormatError):
        decode_envelope((*encoded[:4], encoded[4] + b"x", encoded[5]))


def test_rewrap_changes_only_wrapped_key_and_handle() -> None:
    provider = InMemoryKeyProvider()
    router = KeyProviderRouter((provider,))
    record_cipher = RecordCipher(router, settings(reference="old"))
    envelope = record_cipher.encrypt(item())

    result = record_cipher.rewrap(envelope, settings(reference="new"))

    assert result.changed
    assert result.envelope.key != envelope.key
    assert result.envelope.wrapped_data_key != envelope.wrapped_data_key
    assert result.envelope.ciphertext == envelope.ciphertext
    assert result.envelope.nonce == envelope.nonce
    assert result.envelope.associated_data == envelope.associated_data
    assert record_cipher.decrypt(result.envelope).frames == record_cipher.decrypt(envelope).frames


def test_destroyed_key_cannot_decrypt() -> None:
    record_cipher, provider = cipher()
    envelope = record_cipher.encrypt(item())
    provider.destroy(envelope.key, "revoked")

    with pytest.raises(KeyRevoked):
        record_cipher.decrypt(envelope)


class FakePasswordBackend:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}
        self.locked = False

    def get_password(self, service: str, username: str) -> str | None:
        if self.locked:
            raise keyring_errors.KeyringLocked("locked")
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        if self.locked:
            raise keyring_errors.KeyringLocked("locked")
        self.values[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.values.pop((service, username), None)


def test_os_keyring_create_rotate_and_destroy() -> None:
    backend = FakePasswordBackend()
    provider = OSKeyringProvider(backend=backend)
    first = provider.active_key(KeyRequest(KeyPurpose.RECORD, True, "records"))
    second = provider.rotate(first, "scheduled")

    assert second.version == 2
    assert provider.destroy(first, "revoked").destroyed
    with pytest.raises(KeyProviderUnavailable):
        provider.unwrap_data_key(first, b"invalid", b"aad")


def test_os_keyring_locked_is_not_unavailable() -> None:
    backend = FakePasswordBackend()
    backend.locked = True
    provider = OSKeyringProvider(backend=backend)

    assert provider.health_check().state is KeyProviderState.LOCKED
    with pytest.raises(KeyProviderLocked):
        provider.active_key(KeyRequest(KeyPurpose.RECORD, True, "records"))


def test_local_store_recovery_permissions_and_wrong_passphrase(tmp_path: Path) -> None:
    path = tmp_path / "keys.json"
    first = LocalKeyStoreProvider(path, lambda: b"correct passphrase")
    handle = first.active_key(KeyRequest(KeyPurpose.RECORD, True, "records"))
    wrapped = first.wrap_data_key(handle, b"x" * 32, b"aad")

    reopened = LocalKeyStoreProvider(path, lambda: b"correct passphrase")
    assert reopened.unwrap_data_key(handle, wrapped, b"aad") == bytearray(b"x" * 32)
    assert os.stat(path).st_mode & 0o777 == 0o600

    wrong = LocalKeyStoreProvider(path, lambda: b"wrong passphrase")
    assert wrong.health_check().state is KeyProviderState.LOCKED
    with pytest.raises(KeyProviderLocked):
        wrong.unwrap_data_key(handle, wrapped, b"aad")


def test_local_store_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("{}")
    path = tmp_path / "keys.json"
    path.symlink_to(target)
    provider = LocalKeyStoreProvider(path, lambda: b"passphrase")

    assert provider.health_check().state is KeyProviderState.INVALID


class UnavailableProvider(InMemoryKeyProvider):
    def health_check(self) -> KeyProviderHealth:
        return KeyProviderHealth(self.provider_id, KeyProviderState.UNAVAILABLE, "unavailable")


class LockedProvider(InMemoryKeyProvider):
    def health_check(self) -> KeyProviderHealth:
        return KeyProviderHealth(self.provider_id, KeyProviderState.LOCKED, "locked")


@dataclass
class FakeCommandResult:
    returncode: int
    stdout: bytes


class FakeGPGRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.payload: bytes | None = None

    def __call__(
        self, args: list[str], *, input: bytes | None, timeout: float
    ) -> FakeCommandResult:
        del timeout
        self.calls.append(args)
        if "--version" in args or "--list-keys" in args:
            return FakeCommandResult(0, b"ok")
        if "--encrypt" in args:
            assert input is not None
            self.payload = input
            return FakeCommandResult(0, b"gpg-encrypted")
        if "--decrypt" in args:
            assert input == b"gpg-encrypted"
            assert self.payload is not None
            return FakeCommandResult(0, self.payload)
        return FakeCommandResult(1, b"")


def test_gpg_provider_wraps_and_binds_associated_data() -> None:
    runner = FakeGPGRunner()
    provider = GPGKeyProvider(runner=runner)
    handle = provider.active_key(KeyRequest(KeyPurpose.RECORD, False, "recipient"))
    wrapped = provider.wrap_data_key(handle, b"k" * 32, b"aad")

    assert provider.unwrap_data_key(handle, wrapped, b"aad") == bytearray(b"k" * 32)
    with pytest.raises(AuthenticationFailed):
        provider.unwrap_data_key(handle, wrapped, b"other-aad")
    assert all("--batch" in call for call in runner.calls)


def test_fallback_is_explicit_and_only_for_unavailable_primary() -> None:
    primary = UnavailableProvider("primary")
    gpg_runner = FakeGPGRunner()
    gpg = GPGKeyProvider(runner=gpg_runner)
    config = EncryptionSettings(
        provider_id="primary",
        key_reference=CredentialReference(provider_id="primary", reference="records"),
        fallback_key_reference=CredentialReference(provider_id="gpg", reference="recipient"),
    )
    selection = KeyProviderRouter((primary, gpg)).select_for_encryption(
        config, KeyRequest(KeyPurpose.RECORD, True, "records")
    )
    assert selection.used_fallback
    assert selection.provider.provider_id == "gpg"

    locked = LockedProvider("primary")
    with pytest.raises(KeyProviderLocked):
        KeyProviderRouter((locked, gpg)).select_for_encryption(
            config, KeyRequest(KeyPurpose.RECORD, True, "records")
        )


def _cancelled_event() -> threading.Event:
    event = threading.Event()
    event.set()
    return event


def test_processor_outputs_only_envelope_frames_and_honors_cancellation() -> None:
    record_cipher, _ = cipher()
    processor = EncryptionStageProcessor(record_cipher)
    source = item()

    encrypted = processor.process(
        source, PipelineCancellationToken(source.generation, threading.Event())
    )
    envelope = decode_envelope(encrypted.frames)
    assert envelope.record_id == source.record_id
    assert all(frame not in encrypted.frames for frame in source.frames)

    with pytest.raises(Exception, match="encryption_cancelled"):
        processor.process(source, PipelineCancellationToken(source.generation, _cancelled_event()))


def test_encryption_settings_require_explicit_valid_fallback() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="must use gpg"):
        EncryptionSettings(
            provider_id="memory",
            key_reference=CredentialReference(provider_id="memory", reference="records"),
            fallback_key_reference=CredentialReference(provider_id="other", reference="fallback"),
        )
    with pytest.raises(ValidationError, match="must match"):
        EncryptionSettings(
            provider_id="memory",
            key_reference=CredentialReference(provider_id="other", reference="records"),
        )


def test_effective_configuration_hides_primary_and_fallback_references() -> None:
    from local_recall.config.inspection import inspect_effective_configuration
    from local_recall.config.models import LocalRecallConfig

    configuration = LocalRecallConfig(
        encryption=EncryptionSettings(
            provider_id="memory",
            key_reference=CredentialReference(provider_id="memory", reference="primary-name"),
            fallback_key_reference=CredentialReference(
                provider_id="gpg", reference="fallback-fingerprint"
            ),
        )
    )
    rendered = inspect_effective_configuration(configuration)

    assert rendered["encryption"]["key_reference"]["reference"] == "<configured>"
    assert rendered["encryption"]["fallback_key_reference"]["reference"] == "<configured>"
    assert "primary-name" not in str(rendered)
    assert "fallback-fingerprint" not in str(rendered)


def test_random_nonces_do_not_repeat_in_sample() -> None:
    record_cipher, _ = cipher()
    nonces = {record_cipher.encrypt(item()).nonce for _ in range(256)}

    assert len(nonces) == 256
