from __future__ import annotations

import base64

from local_recall.config import (
    CustomRedactionPattern,
    HighEntropySettings,
    RedactionAllowlist,
)
from local_recall.domain.redaction import RedactionKind
from local_recall.redaction import DeterministicSecretDetector, shannon_entropy


def _aws_key() -> str:
    return "AK" + "IA" + "A1B2C3D4E5F6G7H8"


def _github_token() -> str:
    return "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1L2"


def _google_key() -> str:
    body = "".join(
        str(index % 10) if index % 2 == 0 else chr(ord("a") + index % 26) for index in range(35)
    )
    return "AIza" + body


def test_builtin_secret_corpus_detects_common_providers_and_credentials() -> None:
    samples = {
        RedactionKind.API_TOKEN: (
            _aws_key(),
            "sk_" + "live_" + "a1B2c3D4e5F6g7H8i9J0",
            _google_key(),
        ),
        RedactionKind.ACCESS_TOKEN: (
            _github_token(),
            "".join(("xox", "b-1234567890-", "abcdefghijklmnop")),
            "".join(
                (
                    "eyJhbGciOiJI",
                    "UzI1NiJ9.",
                    "eyJzdWIiOiIx",
                    "MjM0NTY3ODkwIn0.",
                    "abcdefghi",
                    "123456789",
                )
            ),
        ),
        RedactionKind.PASSWORD: ("".join(("pass", "word", "=", "synthetic-", "passphrase")),),
        RedactionKind.AUTHORIZATION_HEADER: (
            "Authorization: Bearer " + "syntheticBearerToken123456",
        ),
        RedactionKind.CONNECTION_STRING: (
            "".join(("postgres", "://", "synthetic", ":", "secret-value", "@localhost/db")),
            "".join(("Account", "Key=", "QWxwaGEyMDE0", "U2VjcmV0S2V5", "PT0=")),
        ),
        RedactionKind.EMAIL: ("analyst@example.test",),
        RedactionKind.USERNAME: ("username=synthetic-user",),
        RedactionKind.PRIVATE_KEY: (
            "-----BEGIN " + "PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----",
        ),
    }
    detector = DeterministicSecretDetector()

    for expected_kind, values in samples.items():
        for value in values:
            result = detector.scan(value)
            assert any(item.kind is expected_kind for item in result.matches), value


def test_encoded_variants_redact_the_entire_encoded_token() -> None:
    detector = DeterministicSecretDetector()
    raw = "Authorization: Bearer " + "encodedTokenValue123456"
    base64_value = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
    percent_value = "Authorization%3A%20Bearer%20encodedTokenValue123456"

    for value in (base64_value, percent_value):
        result = detector.scan(value)
        encoded = [item for item in result.matches if item.detector_id.startswith("encoded:")]
        assert encoded
        assert encoded[0].start == 0
        assert encoded[0].end == len(value)


def test_custom_patterns_and_exact_allowlists_are_pattern_scoped() -> None:
    detector = DeterministicSecretDetector(
        custom_patterns=(
            CustomRedactionPattern(pattern_id="ticket-secret", pattern=r"SEC-[0-9]{8}"),
        ),
        allowlists=(
            RedactionAllowlist(
                allowlist_id="known-demo",
                pattern_id="custom:ticket-secret",
                exact_values=("SEC-00000000",),
            ),
        ),
    )

    result = detector.scan("SEC-00000000 SEC-12345678")

    assert len(result.allowlisted) == 1
    assert result.allowlisted[0].allowlist_id == "known-demo"
    assert len(result.allowlisted[0].value_digest) == 64
    assert [item.matched_text for item in result.matches] == ["SEC-12345678"]
    assert "SEC-00000000" not in repr(result.allowlisted[0])


def test_entropy_thresholds_have_measured_synthetic_fixtures() -> None:
    detector = DeterministicSecretDetector(
        entropy=HighEntropySettings(
            min_length=20,
            min_bits_per_character=3.5,
            hex_min_length=32,
            max_token_length=128,
        )
    )
    positives = (
        "A9f_2Kp7-Lm4Qx8Vn1Zr5T",
        "".join(format((index * 7) % 16, "x") for index in range(32)),
        "R2d2C3poBB8__randomizedToken99",
    )
    negatives = (
        "thisisalongnaturalwordwithoutclasses",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "2026-07-18T14:00:00Z",
        "local-recall-documentation-title",
    )

    true_positives = sum(
        any(item.kind is RedactionKind.HIGH_ENTROPY_SECRET for item in detector.scan(value).matches)
        for value in positives
    )
    false_positives = sum(
        any(item.kind is RedactionKind.HIGH_ENTROPY_SECRET for item in detector.scan(value).matches)
        for value in negatives
    )

    assert true_positives == len(positives)
    assert false_positives == 0
    assert shannon_entropy(positives[0]) >= 3.5
