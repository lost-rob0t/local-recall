from __future__ import annotations

import inspect
import threading
from datetime import UTC, datetime
from typing import get_type_hints

from local_recall.config.manager import ConfigurationSnapshot
from local_recall.config.models import CredentialReference, EncryptionSettings, LocalRecallConfig
from local_recall.crypto import (
    EncryptionLifecyclePreflight,
    EncryptionStageProcessor,
    InMemoryKeyProvider,
    KeyProviderRouter,
)
from local_recall.crypto.gpg_provider import _AsyncioCommandRunner
from local_recall.crypto.models import KeyProviderHealth, KeyProviderState
from local_recall.domain.crypto import EncryptedRecordEnvelope
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.lifecycle.gate import CaptureWorkPermit
from local_recall.lifecycle.messages import (
    LifecycleFaultCode,
    LifecyclePreflightRequest,
)
from local_recall.pipeline.models import EncryptedStageItem, RedactedStageItem
from local_recall.ports.storage import StorageBackend


class UnavailableProvider(InMemoryKeyProvider):
    def health_check(self) -> KeyProviderHealth:
        return KeyProviderHealth(self.provider_id, KeyProviderState.UNAVAILABLE, "unavailable")


def test_storage_and_pipeline_types_enforce_encrypted_boundary() -> None:
    storage_hints = get_type_hints(StorageBackend.put)
    processor_hints = get_type_hints(EncryptionStageProcessor.process)

    assert storage_hints["envelope"] is EncryptedRecordEnvelope
    assert processor_hints["item"] is RedactedStageItem
    assert processor_hints["return"] is EncryptedStageItem


def test_gpg_runner_uses_exec_without_shell_or_plaintext_file() -> None:
    source = inspect.getsource(_AsyncioCommandRunner)

    assert "create_subprocess_exec" in source
    assert "create_subprocess_shell" not in source
    assert "shell=True" not in source
    assert "NamedTemporaryFile" not in source


def test_unavailable_encryption_faults_lifecycle_preflight() -> None:
    provider = UnavailableProvider("primary")
    preflight = EncryptionLifecyclePreflight(KeyProviderRouter((provider,)))
    configuration = LocalRecallConfig(
        encryption=EncryptionSettings(
            provider_id="primary",
            key_reference=CredentialReference(provider_id="primary", reference="records"),
        )
    )
    request = LifecyclePreflightRequest(
        configuration=ConfigurationSnapshot(
            configuration=configuration,
            revision="config-revision",
            source="synthetic",
            loaded_at=datetime.now(UTC),
        ),
        generation=CaptureGeneration(1),
        deadline_monotonic_ns=10**18,
        cancellation=CaptureWorkPermit(
            CaptureGeneration(1),
            "config-revision",
            threading.Event(),
        ),
    )

    result = preflight.check(request)

    assert not result.ready
    assert result.fault_code is LifecycleFaultCode.ENCRYPTION_UNAVAILABLE


def test_plaintext_key_material_is_not_a_configuration_field() -> None:
    from pydantic import ValidationError

    forbidden_name = "key" + "_material"
    try:
        LocalRecallConfig.model_validate(
            {
                "schema_version": 1,
                "encryption": {forbidden_name: "synthetic-value"},
            }
        )
    except ValidationError as exc:
        assert "Extra inputs are not permitted" in str(exc)
    else:
        raise AssertionError("plaintext key material was accepted")
