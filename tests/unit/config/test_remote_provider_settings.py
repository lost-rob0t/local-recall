from __future__ import annotations

import pytest
from pydantic import ValidationError

from local_recall.config import RemoteProviderSettings


def _enabled_provider(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "provider_id": "openrouter-main",
        "enabled": True,
        "kind": "openrouter",
        "endpoint": "https://openrouter.ai/api/v1/chat/completions",
        "model_id": "anthropic/claude-sonnet-4.6",
        "credential_reference": {
            "provider_id": "os-keyring",
            "reference": "openrouter-main",
        },
    }
    data.update(overrides)
    return data


def test_enabled_remote_provider_declares_strategy_endpoint_and_model() -> None:
    provider = RemoteProviderSettings.model_validate(_enabled_provider())

    assert provider.kind == "openrouter"
    assert provider.endpoint == "https://openrouter.ai/api/v1/chat/completions"
    assert provider.model_id == "anthropic/claude-sonnet-4.6"


@pytest.mark.parametrize("field", ["kind", "endpoint", "model_id"])
def test_enabled_remote_provider_requires_executable_strategy_configuration(field: str) -> None:
    data = _enabled_provider()
    del data[field]

    with pytest.raises(ValidationError, match=field):
        RemoteProviderSettings.model_validate(data)


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://openrouter.ai/api/v1/chat/completions",
        "https://user@openrouter.ai/api/v1/chat/completions",
        "https://openrouter.ai/api/v1/chat/completions?token=forbidden",
        "https://openrouter.ai/api/v1/chat/completions#fragment",
    ],
)
def test_remote_provider_configuration_rejects_unsafe_endpoint(endpoint: str) -> None:
    with pytest.raises(ValidationError, match="endpoint"):
        RemoteProviderSettings.model_validate(_enabled_provider(endpoint=endpoint))
