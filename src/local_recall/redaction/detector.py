from __future__ import annotations

import base64
import binascii
import hashlib
import html
import math
import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import unquote

from local_recall.config.models import (
    CustomRedactionPattern,
    HighEntropySettings,
    RedactionAllowlist,
)
from local_recall.domain.metadata import SourceConfidence
from local_recall.domain.redaction import RedactionKind

from .models import AllowlistedMatch, DetectionResult, SecretMatch


@dataclass(frozen=True, slots=True)
class _Pattern:
    detector_id: str
    kind: RedactionKind
    expression: re.Pattern[str]
    group: str | int = 0
    confidence: float = 1.0


_BUILTINS: tuple[_Pattern, ...] = (
    _Pattern(
        "private-key",
        RedactionKind.PRIVATE_KEY,
        re.compile(
            r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?"
            r"-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    _Pattern(
        "authorization-header",
        RedactionKind.AUTHORIZATION_HEADER,
        re.compile(
            r"(?i)\bauthorization\s*:\s*(?P<secret>(?:bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{8,})"
        ),
        "secret",
    ),
    _Pattern(
        "aws-access-key",
        RedactionKind.API_TOKEN,
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ),
    _Pattern(
        "github-token",
        RedactionKind.ACCESS_TOKEN,
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b"),
    ),
    _Pattern(
        "slack-token",
        RedactionKind.ACCESS_TOKEN,
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,255}\b"),
    ),
    _Pattern(
        "stripe-secret",
        RedactionKind.API_TOKEN,
        re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,255}\b"),
    ),
    _Pattern(
        "google-api-key",
        RedactionKind.API_TOKEN,
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ),
    _Pattern(
        "jwt",
        RedactionKind.ACCESS_TOKEN,
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    ),
    _Pattern(
        "password-assignment",
        RedactionKind.PASSWORD,
        re.compile(r"(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*[\"']?(?P<secret>[^\s\"',;]{4,256})"),
        "secret",
    ),
    _Pattern(
        "username-assignment",
        RedactionKind.USERNAME,
        re.compile(
            r"(?i)\b(?:username|user|login)\b\s*[:=]\s*[\"']?(?P<secret>[A-Za-z0-9_.@-]{2,128})"
        ),
        "secret",
    ),
    _Pattern(
        "generic-token-assignment",
        RedactionKind.ACCESS_TOKEN,
        re.compile(
            r"(?i)\b(?:access[_ -]?token|api[_ -]?key|secret[_ -]?key|client[_ -]?secret)\b"
            r"\s*[:=]\s*[\"']?(?P<secret>[A-Za-z0-9._~+/=-]{8,512})"
        ),
        "secret",
    ),
    _Pattern(
        "credentialed-connection-string",
        RedactionKind.CONNECTION_STRING,
        re.compile(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqps?|mssql)://"
            r"[^\s:/?#]+:[^\s@/?#]+@[^\s]+"
        ),
    ),
    _Pattern(
        "account-key-connection-string",
        RedactionKind.CONNECTION_STRING,
        re.compile(r"(?i)\bAccountKey=(?P<secret>[A-Za-z0-9+/=]{16,512})"),
        "secret",
    ),
    _Pattern(
        "email-address",
        RedactionKind.EMAIL,
        re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}"),
        confidence=0.99,
    ),
)

_SENSITIVE_METADATA_NAMES: tuple[tuple[re.Pattern[str], str, RedactionKind], ...] = (
    (
        re.compile(r"(?i)(?:^|[._-])(?:password|passwd|pwd)(?:$|[._-])"),
        "password-field",
        RedactionKind.PASSWORD,
    ),
    (
        re.compile(r"(?i)(?:^|[._-])(?:authorization|auth)(?:$|[._-])"),
        "authorization-field",
        RedactionKind.AUTHORIZATION_HEADER,
    ),
    (
        re.compile(r"(?i)(?:^|[._-])(?:api.?key|access.?token|secret)(?:$|[._-])"),
        "token-field",
        RedactionKind.ACCESS_TOKEN,
    ),
    (
        re.compile(r"(?i)(?:^|[._-])(?:username|user|login)(?:$|[._-])"),
        "username-field",
        RedactionKind.USERNAME,
    ),
    (re.compile(r"(?i)(?:^|[._-])(?:email|mail)(?:$|[._-])"), "email-field", RedactionKind.EMAIL),
    (
        re.compile(r"(?i)(?:^|[._-])(?:connection.?string|dsn)(?:$|[._-])"),
        "connection-field",
        RedactionKind.CONNECTION_STRING,
    ),
)

_PERCENT_CANDIDATE = re.compile(r"[A-Za-z0-9_.~+-]*(?:%[0-9A-Fa-f]{2})[A-Za-z0-9_.~%+-]{7,}")
_BASE64_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_-])")


class DeterministicSecretDetector:
    def __init__(
        self,
        *,
        entropy: HighEntropySettings | None = None,
        custom_patterns: tuple[CustomRedactionPattern, ...] = (),
        allowlists: tuple[RedactionAllowlist, ...] = (),
    ) -> None:
        self._entropy = entropy or HighEntropySettings()
        self._patterns = (*_BUILTINS, *self._compile_custom(custom_patterns))
        self._allowlists = self._index_allowlists(allowlists)

    def scan(self, text: str) -> DetectionResult:
        if not text:
            return DetectionResult((), ())
        matches: list[SecretMatch] = []
        allowlisted: list[AllowlistedMatch] = []
        self._scan_direct(text, matches, allowlisted)
        self._scan_encoded(text, matches, allowlisted)
        if self._entropy.enabled:
            self._scan_entropy(text, matches, allowlisted)
        return DetectionResult(
            matches=tuple(self._deduplicate(matches)),
            allowlisted=tuple(self._deduplicate_allowlisted(allowlisted)),
        )

    def sensitive_metadata_name(self, name: str) -> tuple[str, RedactionKind] | None:
        for expression, detector_id, kind in _SENSITIVE_METADATA_NAMES:
            if expression.search(name):
                return detector_id, kind
        return None

    def _scan_direct(
        self,
        text: str,
        matches: list[SecretMatch],
        allowlisted: list[AllowlistedMatch],
    ) -> None:
        decoded_html = html.unescape(text)
        views = ((text, 0),)
        if decoded_html != text and len(decoded_html) == len(text):
            views = (*views, (decoded_html, 0))
        for view, offset in views:
            for pattern in self._patterns:
                for found in pattern.expression.finditer(view):
                    start, end = found.span(pattern.group)
                    candidate = found.group(pattern.group)
                    self._record_candidate(
                        detector_id=pattern.detector_id,
                        kind=pattern.kind,
                        start=offset + start,
                        end=offset + end,
                        candidate=candidate,
                        confidence=pattern.confidence,
                        matches=matches,
                        allowlisted=allowlisted,
                    )

    def _scan_encoded(
        self,
        text: str,
        matches: list[SecretMatch],
        allowlisted: list[AllowlistedMatch],
    ) -> None:
        for found in _PERCENT_CANDIDATE.finditer(text):
            raw = found.group(0)
            decoded = unquote(raw)
            self._record_encoded_matches(
                raw, decoded, found.start(), found.end(), matches, allowlisted
            )
        for found in _BASE64_CANDIDATE.finditer(text):
            raw = found.group(0)
            decoded = self._decode_base64(raw)
            if decoded is not None:
                self._record_encoded_matches(
                    raw, decoded, found.start(), found.end(), matches, allowlisted
                )

    def _record_encoded_matches(
        self,
        raw: str,
        decoded: str,
        start: int,
        end: int,
        matches: list[SecretMatch],
        allowlisted: list[AllowlistedMatch],
    ) -> None:
        inner_matches: list[SecretMatch] = []
        inner_allowlisted: list[AllowlistedMatch] = []
        self._scan_direct(decoded, inner_matches, inner_allowlisted)
        for inner in inner_matches:
            self._record_candidate(
                detector_id=f"encoded:{inner.detector_id}",
                kind=inner.kind,
                start=start,
                end=end,
                candidate=raw,
                confidence=min(inner.confidence.value, 0.98),
                matches=matches,
                allowlisted=allowlisted,
                decoded_candidate=decoded[inner.start : inner.end],
                inner_detector_id=inner.detector_id,
            )

    def _scan_entropy(
        self,
        text: str,
        matches: list[SecretMatch],
        allowlisted: list[AllowlistedMatch],
    ) -> None:
        expression = re.compile(
            rf"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_=-]"
            rf"{{{self._entropy.min_length},{self._entropy.max_token_length}}}"
            rf"(?![A-Za-z0-9+/_=-])"
        )
        occupied = tuple((item.start, item.end) for item in matches)
        for found in expression.finditer(text):
            candidate = found.group(0)
            if any(found.start() < end and found.end() > start for start, end in occupied):
                continue
            if not self._looks_secret_like(candidate):
                continue
            entropy = shannon_entropy(candidate)
            threshold = self._entropy.min_bits_per_character
            if self._is_hex(candidate):
                if len(candidate) < self._entropy.hex_min_length:
                    continue
                threshold = min(threshold, 3.0)
            if entropy < threshold:
                continue
            confidence = min(0.99, 0.65 + max(0.0, entropy - threshold) / 4.0)
            self._record_candidate(
                detector_id="high-entropy",
                kind=RedactionKind.HIGH_ENTROPY_SECRET,
                start=found.start(),
                end=found.end(),
                candidate=candidate,
                confidence=confidence,
                matches=matches,
                allowlisted=allowlisted,
            )

    def _record_candidate(
        self,
        *,
        detector_id: str,
        kind: RedactionKind,
        start: int,
        end: int,
        candidate: str,
        confidence: float,
        matches: list[SecretMatch],
        allowlisted: list[AllowlistedMatch],
        decoded_candidate: str | None = None,
        inner_detector_id: str | None = None,
    ) -> None:
        allowlist = self._allowlist_for(detector_id, candidate)
        if allowlist is None and inner_detector_id is not None and decoded_candidate is not None:
            allowlist = self._allowlist_for(inner_detector_id, decoded_candidate)
        if allowlist is not None:
            allowlisted.append(
                AllowlistedMatch(
                    detector_id=detector_id,
                    allowlist_id=allowlist,
                    start=start,
                    end=end,
                    value_digest=hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
                )
            )
            return
        matches.append(
            SecretMatch(
                detector_id=detector_id,
                kind=kind,
                start=start,
                end=end,
                confidence=SourceConfidence(confidence),
                matched_text=candidate,
            )
        )

    def _allowlist_for(self, detector_id: str, candidate: str) -> str | None:
        for allowlist_id, values in self._allowlists.get(detector_id, ()):
            if candidate in values:
                return allowlist_id
        return None

    @staticmethod
    def _compile_custom(patterns: tuple[CustomRedactionPattern, ...]) -> tuple[_Pattern, ...]:
        return tuple(
            _Pattern(
                detector_id=f"custom:{pattern.pattern_id}",
                kind=RedactionKind.CUSTOM_PATTERN,
                expression=re.compile(pattern.pattern),
                confidence=1.0,
            )
            for pattern in patterns
        )

    @staticmethod
    def _index_allowlists(
        allowlists: tuple[RedactionAllowlist, ...],
    ) -> dict[str, tuple[tuple[str, frozenset[str]], ...]]:
        result: dict[str, list[tuple[str, frozenset[str]]]] = {}
        for item in allowlists:
            result.setdefault(item.pattern_id, []).append(
                (item.allowlist_id, frozenset(item.exact_values))
            )
        return {key: tuple(value) for key, value in result.items()}

    @staticmethod
    def _decode_base64(candidate: str) -> str | None:
        padded = candidate + "=" * (-len(candidate) % 4)
        try:
            decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
            return decoded.decode("utf-8")
        except binascii.Error, UnicodeDecodeError, ValueError:
            return None

    @staticmethod
    def _is_hex(candidate: str) -> bool:
        return bool(re.fullmatch(r"[0-9A-Fa-f]+", candidate))

    @staticmethod
    def _looks_secret_like(candidate: str) -> bool:
        if len(set(candidate)) < 5:
            return False
        classes = (
            any(char.islower() for char in candidate),
            any(char.isupper() for char in candidate),
            any(char.isdigit() for char in candidate),
            any(char in "+/_=-" for char in candidate),
        )
        if re.fullmatch(r"[0-9A-Fa-f]+", candidate):
            return True
        return sum(classes) >= 3

    @staticmethod
    def _deduplicate(matches: list[SecretMatch]) -> list[SecretMatch]:
        ordered = sorted(
            matches, key=lambda item: (item.start, -(item.end - item.start), item.detector_id)
        )
        result: list[SecretMatch] = []
        seen: set[tuple[int, int, RedactionKind]] = set()
        for item in ordered:
            key = (item.start, item.end, item.kind)
            if key in seen:
                continue
            seen.add(key)
            result.append(item)
        return result

    @staticmethod
    def _deduplicate_allowlisted(items: list[AllowlistedMatch]) -> list[AllowlistedMatch]:
        result: list[AllowlistedMatch] = []
        seen: set[tuple[str, str, int, int]] = set()
        for item in sorted(items, key=lambda value: (value.start, value.end, value.detector_id)):
            key = (item.detector_id, item.allowlist_id, item.start, item.end)
            if key not in seen:
                seen.add(key)
                result.append(item)
        return result


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())
