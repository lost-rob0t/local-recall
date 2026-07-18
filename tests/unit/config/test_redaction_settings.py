from __future__ import annotations

import pytest
from pydantic import ValidationError

from local_recall.config import (
    CustomRedactionPattern,
    LocalRecallConfig,
    OCRSettings,
    RedactionAllowlist,
    RedactionSettings,
    inspect_effective_configuration,
)


def test_ocr_provider_is_fixed_to_local_tesseract_binary() -> None:
    assert OCRSettings().provider_id == "tesseract-local"
    assert OCRSettings(executable="/nix/store/example/bin/tesseract").executable.endswith(
        "/tesseract"
    )

    with pytest.raises(ValidationError, match="tesseract binary"):
        OCRSettings(executable="/bin/sh")


def test_allowlists_must_reference_known_narrow_patterns() -> None:
    with pytest.raises(ValidationError, match="unknown pattern"):
        RedactionSettings(
            allowlists=(
                RedactionAllowlist(
                    allowlist_id="invalid-target",
                    pattern_id="missing-detector",
                    exact_values=("synthetic",),
                ),
            )
        )

    settings = RedactionSettings(
        custom_patterns=(CustomRedactionPattern(pattern_id="ticket", pattern=r"SEC-[0-9]{8}"),),
        allowlists=(
            RedactionAllowlist(
                allowlist_id="demo-ticket",
                pattern_id="custom:ticket",
                exact_values=("SEC-00000000",),
            ),
        ),
    )

    assert settings.allowlists[0].pattern_id == "custom:ticket"


def test_model_assistance_cannot_replace_deterministic_filters() -> None:
    with pytest.raises(ValidationError, match="requires deterministic filters"):
        RedactionSettings(
            deterministic_required=False,
            model_assistance_enabled=True,
        )


def test_effective_configuration_hides_allowlist_values() -> None:
    marker = "demo@example.test"
    configuration = LocalRecallConfig(
        redaction=RedactionSettings(
            allowlists=(
                RedactionAllowlist(
                    allowlist_id="demo-email",
                    pattern_id="email-address",
                    exact_values=(marker,),
                ),
            )
        )
    )

    rendered = inspect_effective_configuration(configuration)

    assert rendered["redaction"]["allowlists"] == [
        {
            "allowlist_id": "demo-email",
            "pattern_id": "email-address",
            "exact_values": "<configured:1>",
        }
    ]
    assert marker not in str(rendered)
