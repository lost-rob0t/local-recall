from __future__ import annotations

from importlib import import_module

import pytest

routing = import_module("local_recall.routing")
EgressAuthorization = routing.EgressAuthorization
EgressDataClass = routing.EgressDataClass
EgressDeniedError = routing.EgressDeniedError
EgressGate = routing.EgressGate
EgressPayload = routing.EgressPayload


def _authorization(
    *data_classes: object,
    max_payload_bytes: int = 4096,
) -> object:
    return EgressAuthorization(
        authorization_id="auth-egress-1",
        provider_id="remote-provider",
        data_classes=frozenset(data_classes),
        max_payload_bytes=max_payload_bytes,
    )


def test_safe_redacted_text_is_approved_with_content_free_control_metadata() -> None:
    gate = EgressGate()
    payload = EgressPayload(text="A bounded already-redacted answer context.")

    approved = gate.approve(
        payload,
        _authorization(EgressDataClass.REDACTED_TEXT),
    )

    assert approved.authorization_id == "auth-egress-1"
    assert approved.provider_id == "remote-provider"
    assert approved.data_classes == frozenset({EgressDataClass.REDACTED_TEXT})
    assert approved.payload_bytes == len(payload.text.encode("utf-8"))
    assert approved.payload_sha256
    assert approved.text == payload.text
    assert payload.text not in repr(approved)


def test_payload_is_rescanned_and_secret_match_fails_closed() -> None:
    gate = EgressGate()
    secret = "Authorization: Bearer ghp_1234567890abcdefghijklmnopqrstuv"  # pragma: allowlist secret

    with pytest.raises(EgressDeniedError, match="secret-detected") as captured:
        gate.approve(
            EgressPayload(text=secret),
            _authorization(EgressDataClass.REDACTED_TEXT),
        )

    assert secret not in repr(captured.value)
    assert secret not in str(captured.value)


def test_sensitive_metadata_name_is_rejected_before_remote_egress() -> None:
    gate = EgressGate()

    with pytest.raises(EgressDeniedError, match="sensitive-metadata"):
        gate.approve(
            EgressPayload(metadata=(("api_key", "already-redacted"),)),
            _authorization(EgressDataClass.APPROVED_METADATA),
        )


def test_authorization_payload_limit_is_enforced_on_canonical_bytes() -> None:
    gate = EgressGate()

    with pytest.raises(EgressDeniedError, match="payload-too-large"):
        gate.approve(
            EgressPayload(text="abcd"),
            _authorization(EgressDataClass.REDACTED_TEXT, max_payload_bytes=3),
        )


def test_image_egress_is_denied_without_explicit_image_class() -> None:
    gate = EgressGate()

    with pytest.raises(EgressDeniedError, match="egress-data-class-denied"):
        gate.approve(
            EgressPayload(image=b"synthetic-redacted-image"),
            _authorization(EgressDataClass.REDACTED_TEXT),
        )


def test_mixed_payload_requires_every_data_class_to_be_authorized() -> None:
    gate = EgressGate()

    with pytest.raises(EgressDeniedError, match="egress-data-class-denied"):
        gate.approve(
            EgressPayload(
                text="safe redacted text",
                metadata=(("application", "editor"),),
            ),
            _authorization(EgressDataClass.REDACTED_TEXT),
        )
