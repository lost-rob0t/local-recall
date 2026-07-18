from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from local_recall.config import RedactionAllowlist, RedactionSettings
from local_recall.domain.redaction import PixelRegion, RedactionKind, RedactionTarget
from local_recall.ports.redaction import RedactionRequest
from local_recall.redaction import DeterministicRedactionPolicy, RedactionFailure

from .support import gray_frame, metadata, ocr


def test_policy_masks_pixels_text_and_sensitive_metadata_before_output() -> None:
    secret = "".join(("pass", "word", "=", "synthetic-", "passphrase"))
    frame = gray_frame(
        width=len(secret),
        height=2,
        pixels=secret.encode() * 2,
        context=metadata(
            ("application", "editor"),
            ("window.password", "synthetic-passphrase"),
            ("title", "safe title"),
        ),
    )
    result = ocr(frame, (secret, 0.99, PixelRegion(0, 0, len(secret), 1)))
    policy = DeterministicRedactionPolicy(now=lambda: datetime(2026, 1, 2, tzinfo=UTC))

    record = asyncio.run(policy.redact(RedactionRequest(frame, result, policy.revision)))

    assert record.frame.ocr_text == ("password=[REDACTED]",)
    assert record.frame.pixels[: len(secret)] == b"\x00" * len(secret)
    assert record.frame.pixels[len(secret) :] == secret.encode()
    assert record.frame.metadata.get("window.password") is None
    assert record.frame.metadata.get("title") == "safe title"
    assert any(item.kind is RedactionKind.PASSWORD for item in record.frame.findings)
    assert {item.target for item in record.frame.findings} >= {
        RedactionTarget.PIXELS,
        RedactionTarget.OCR_TEXT,
        RedactionTarget.METADATA,
    }
    assert secret not in repr(record)


def test_low_confidence_ocr_is_conservatively_redacted() -> None:
    frame = gray_frame(width=12, height=1, pixels=b"uncertain123")
    result = ocr(frame, ("uncertain123", 0.25, PixelRegion(0, 0, 12, 1)))
    policy = DeterministicRedactionPolicy(RedactionSettings(low_confidence_threshold=0.6))

    record = asyncio.run(policy.redact(RedactionRequest(frame, result, policy.revision)))

    assert record.frame.ocr_text == ("[REDACTED]",)
    assert record.frame.pixels == b"\x00" * 12
    assert any(item.detector_id == "low-confidence-ocr" for item in record.frame.findings)


def test_allowlist_decisions_are_auditable_without_raw_values() -> None:
    value = "SEC-00000000"
    settings = RedactionSettings(
        custom_patterns=(),
        allowlists=(
            RedactionAllowlist(
                allowlist_id="known-email",
                pattern_id="email-address",
                exact_values=("demo@example.test",),
            ),
        ),
    )
    frame = gray_frame(width=17, height=1, pixels=b"X" * 17)
    result = ocr(frame, ("demo@example.test", 0.99, PixelRegion(0, 0, 17, 1)))
    policy = DeterministicRedactionPolicy(settings)

    record = asyncio.run(policy.redact(RedactionRequest(frame, result, policy.revision)))

    assert record.frame.ocr_text == ("demo@example.test",)
    assert len(record.frame.allowlist_decisions) == 1
    decision = record.frame.allowlist_decisions[0]
    assert decision.allowlist_id == "known-email"
    assert "demo@example.test" not in repr(decision)
    assert value not in repr(decision)


def test_invalid_ocr_regions_reject_the_entire_record() -> None:
    frame = gray_frame(width=4, height=1, pixels=b"abcd")
    result = ocr(frame, ("password=bad", 0.99, PixelRegion(3, 0, 4, 1)))
    policy = DeterministicRedactionPolicy()

    with pytest.raises(RedactionFailure):
        asyncio.run(policy.redact(RedactionRequest(frame, result, policy.revision)))
