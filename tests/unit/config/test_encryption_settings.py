from __future__ import annotations

import pytest
from pydantic import ValidationError

from local_recall.config import EncryptionSettings, inspect_effective_configuration
from local_recall.config.models import LocalRecallConfig


def test_gpg_fallback_requires_explicit_provider_and_recipient() -> None:
    with pytest.raises(ValidationError, match="GPG fallback requires gpg_recipient"):
        EncryptionSettings(
            provider_id="os-keyring",
            fallback_provider_id="gpg",
        )

    with pytest.raises(ValidationError, match="requires fallback_provider_id"):
        EncryptionSettings(
            provider_id="os-keyring",
            gpg_recipient="synthetic-recipient",
        )


def test_primary_and_fallback_must_differ() -> None:
    with pytest.raises(ValidationError, match="must differ"):
        EncryptionSettings(
            provider_id="gpg",
            fallback_provider_id="gpg",
            gpg_recipient="synthetic-recipient",
        )


def test_only_supported_authenticated_algorithm_is_accepted() -> None:
    with pytest.raises(ValidationError):
        EncryptionSettings(algorithm="unversioned-cipher")  # type: ignore[arg-type]


def test_effective_configuration_hides_gpg_recipient() -> None:
    configuration = LocalRecallConfig(
        encryption=EncryptionSettings(
            provider_id="os-keyring",
            fallback_provider_id="gpg",
            gpg_recipient="recipient-must-not-appear",
        )
    )

    rendered = inspect_effective_configuration(configuration)

    assert rendered["encryption"]["gpg_recipient"] == "<configured>"
    assert "recipient-must-not-appear" not in str(rendered)
