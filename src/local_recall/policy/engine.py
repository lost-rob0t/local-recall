from __future__ import annotations

import hashlib
import ipaddress
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from zoneinfo import ZoneInfo

from local_recall.config.models import CaptureRule, LocalRecallConfig, PrivacyProfile, RuleEffect
from local_recall.domain._validation import require_aware, require_nonempty
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import ContextField, ContextMetadata, MetadataScalar
from local_recall.domain.policy import (
    PolicyAuthorization,
    PolicyDecision,
    PolicyOperation,
    PolicyPhase,
    PolicyReasonCode,
    PolicyStatus,
    SensitiveScope,
)

_MAX_METADATA_TEXT = 4096
_BUILTIN_SENSITIVE_APPLICATIONS = frozenset(
    {
        "1password",
        "1password-browser",
        "bitwarden",
        "keepass",
        "keepassxc",
        "org.keepassxc.keepassxc",
    }
)
_BUILTIN_LOCK_APPLICATIONS = frozenset(
    {
        "i3lock",
        "light-locker",
        "slock",
        "xsecurelock",
    }
)
_BUILTIN_AUTH_APPLICATIONS = frozenset(
    {
        "gcr-prompter",
        "lxqt-policykit-agent",
        "pinentry",
        "pinentry-gtk-2",
        "pinentry-qt",
        "polkit-gnome-authentication-agent-1",
        "ssh-askpass",
    }
)
_AUTH_TITLE_TOKENS = (
    "authentication required",
    "enter password",
    "password required",
    "unlock keyring",
)
_CAPTURE_SENSITIVE_OPERATIONS = frozenset(
    {
        PolicyOperation.SCREENSHOT,
        PolicyOperation.OCR,
        PolicyOperation.INDEXING,
        PolicyOperation.SUMMARIZATION,
        PolicyOperation.REMOTE_PROVIDER,
    }
)


class _Match(StrEnum):
    MATCH = "match"
    NO_MATCH = "no-match"
    UNKNOWN = "unknown"
    MALFORMED = "malformed"


@dataclass(frozen=True, slots=True, repr=False)
class PolicyEvaluationContext:
    metadata: ContextMetadata
    evaluated_at: datetime
    capture_generation: CaptureGeneration
    full_screen: bool | None = None

    def __post_init__(self) -> None:
        require_aware(self.evaluated_at, "evaluated_at")

    def __repr__(self) -> str:
        return (
            "PolicyEvaluationContext("
            f"evaluated_at={self.evaluated_at!r}, "
            f"capture_generation={self.capture_generation.value!r}, "
            f"full_screen={self.full_screen!r}, metadata={self.metadata!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class _CompiledRule:
    rule: CaptureRule
    rule_id: str
    title_pattern: re.Pattern[str] | None
    normalized_domain: str | None


@dataclass(frozen=True, slots=True, repr=False)
class _TemporarySensitiveContext:
    scope: SensitiveScope
    value: str | int
    expires_at: datetime
    capture_generation: CaptureGeneration


@dataclass(frozen=True, slots=True)
class _EngineSnapshot:
    configuration: LocalRecallConfig
    revision: str
    generation: int
    rules: tuple[_CompiledRule, ...]
    timezone: ZoneInfo
    privacy_mode: bool
    session_locked: bool
    healthy: bool
    last_error_code: str | None
    temporary: tuple[_TemporarySensitiveContext, ...]


class PolicyEngine:
    def __init__(self, configuration: LocalRecallConfig, *, revision: str) -> None:
        require_nonempty(revision, "revision")
        compiled = self._compile(configuration)
        self._lock = threading.RLock()
        self._configuration = configuration
        self._revision = revision
        self._generation = 1
        self._rules = compiled
        self._timezone = ZoneInfo(configuration.rules.timezone)
        self._privacy_mode = False
        self._session_locked = False
        self._healthy = True
        self._last_error_code: str | None = None
        self._temporary: tuple[_TemporarySensitiveContext, ...] = ()

    @property
    def revision(self) -> str:
        with self._lock:
            return self._revision

    def evaluate(
        self,
        operation: PolicyOperation,
        phase: PolicyPhase,
        context: PolicyEvaluationContext,
    ) -> PolicyDecision:
        snapshot = self._snapshot(context.evaluated_at)
        return self._evaluate(snapshot, operation, phase, context)

    def authorize(
        self,
        operation: PolicyOperation,
        phase: PolicyPhase,
        context: PolicyEvaluationContext,
    ) -> PolicyAuthorization:
        decision = self.evaluate(operation, phase, context)
        if not decision.allowed or not decision.certain:
            raise PermissionError(
                f"policy denied: {decision.reason_code.value}"
                + (f" ({decision.rule_id})" if decision.rule_id is not None else "")
            )
        return PolicyAuthorization(
            operation=operation,
            phase=phase,
            policy_revision=decision.policy_revision,
            policy_generation=decision.policy_generation,
            capture_generation=context.capture_generation,
        )

    def is_authorization_current(
        self,
        authorization: PolicyAuthorization,
        *,
        capture_generation: CaptureGeneration | None = None,
    ) -> bool:
        with self._lock:
            if self._privacy_mode or self._session_locked or not self._healthy:
                return False
            if authorization.policy_revision != self._revision:
                return False
            if authorization.policy_generation != self._generation:
                return False
            if capture_generation is None:
                return True
            return authorization.capture_generation == capture_generation

    def set_privacy_mode(self, active: bool) -> None:
        with self._lock:
            if self._privacy_mode == active:
                return
            self._privacy_mode = active
            self._generation += 1
            if active:
                self._temporary = ()

    def set_session_locked(self, locked: bool) -> None:
        with self._lock:
            if self._session_locked == locked:
                return
            self._session_locked = locked
            self._generation += 1
            if locked:
                self._temporary = ()

    def mark_current_sensitive(
        self,
        scope: SensitiveScope,
        context: PolicyEvaluationContext,
        *,
        ttl_seconds: float,
    ) -> None:
        if not 1.0 <= ttl_seconds <= 86_400.0:
            raise ValueError("temporary sensitivity lifetime must be between 1 second and 24 hours")
        value = self._sensitive_scope_value(scope, context.metadata)
        if value is None:
            raise ValueError("required context for temporary sensitivity is unavailable")
        marker = _TemporarySensitiveContext(
            scope=scope,
            value=value,
            expires_at=context.evaluated_at + timedelta(seconds=ttl_seconds),
            capture_generation=context.capture_generation,
        )
        with self._lock:
            retained = tuple(item for item in self._temporary if item.scope is not scope)
            self._temporary = (*retained, marker)
            self._generation += 1

    def clear_temporary_sensitive(self, scope: SensitiveScope | None = None) -> None:
        with self._lock:
            if scope is None:
                if not self._temporary:
                    return
                self._temporary = ()
                self._generation += 1
                return
            retained = tuple(item for item in self._temporary if item.scope is not scope)
            if retained == self._temporary:
                return
            self._temporary = retained
            self._generation += 1

    def replace_policy(self, configuration: LocalRecallConfig, *, revision: str) -> None:
        require_nonempty(revision, "revision")
        try:
            compiled = self._compile(configuration)
            timezone = ZoneInfo(configuration.rules.timezone)
        except Exception:
            with self._lock:
                self._healthy = False
                self._last_error_code = "policy-reload-invalid"
                self._generation += 1
            raise
        with self._lock:
            self._configuration = configuration
            self._revision = revision
            self._rules = compiled
            self._timezone = timezone
            self._temporary = ()
            self._healthy = True
            self._last_error_code = None
            self._generation += 1

    def status(self) -> PolicyStatus:
        with self._lock:
            return PolicyStatus(
                policy_revision=self._revision,
                policy_generation=self._generation,
                enabled_rule_count=sum(1 for rule in self._rules if rule.rule.enabled),
                privacy_mode=self._privacy_mode,
                session_locked=self._session_locked,
                healthy=self._healthy,
                last_error_code=self._last_error_code,
            )

    def _snapshot(self, now: datetime) -> _EngineSnapshot:
        with self._lock:
            temporary = tuple(item for item in self._temporary if item.expires_at > now)
            if temporary != self._temporary:
                self._temporary = temporary
                self._generation += 1
            return _EngineSnapshot(
                configuration=self._configuration,
                revision=self._revision,
                generation=self._generation,
                rules=self._rules,
                timezone=self._timezone,
                privacy_mode=self._privacy_mode,
                session_locked=self._session_locked,
                healthy=self._healthy,
                last_error_code=self._last_error_code,
                temporary=temporary,
            )

    def _evaluate(
        self,
        snapshot: _EngineSnapshot,
        operation: PolicyOperation,
        phase: PolicyPhase,
        context: PolicyEvaluationContext,
    ) -> PolicyDecision:
        if not snapshot.healthy:
            return self._deny(snapshot, operation, phase, PolicyReasonCode.POLICY_UNAVAILABLE)
        if snapshot.privacy_mode:
            return self._deny(snapshot, operation, phase, PolicyReasonCode.PRIVACY_MODE)
        if snapshot.session_locked:
            return self._deny(snapshot, operation, phase, PolicyReasonCode.SESSION_LOCKED)

        if operation in _CAPTURE_SENSITIVE_OPERATIONS:
            context_failure = self._validate_context(snapshot, context)
            if context_failure is not None:
                return self._deny(snapshot, operation, phase, context_failure, certain=False)

        if operation is PolicyOperation.REMOTE_PROVIDER and not self._remote_authorized(snapshot):
            return self._deny(snapshot, operation, phase, PolicyReasonCode.REMOTE_NOT_AUTHORIZED)

        matched_denies: list[_CompiledRule] = []
        matched_allows: list[_CompiledRule] = []
        for rule in snapshot.rules:
            if not rule.rule.enabled or operation not in rule.rule.operations:
                continue
            matched = self._match_rule(rule, snapshot, context)
            if matched is _Match.MALFORMED:
                return self._deny(
                    snapshot,
                    operation,
                    phase,
                    PolicyReasonCode.MALFORMED_CONTEXT,
                    certain=False,
                    rule_id=rule.rule_id,
                )
            if matched is _Match.UNKNOWN:
                return self._deny(
                    snapshot,
                    operation,
                    phase,
                    PolicyReasonCode.REQUIRED_CONTEXT_MISSING,
                    certain=False,
                    rule_id=rule.rule_id,
                )
            if matched is not _Match.MATCH:
                continue
            if rule.rule.effect is RuleEffect.DENY:
                matched_denies.append(rule)
            else:
                matched_allows.append(rule)

        if matched_denies:
            strongest = min(
                matched_denies,
                key=lambda item: (-item.rule.priority, item.rule_id),
            )
            return self._deny(
                snapshot,
                operation,
                phase,
                PolicyReasonCode.EXPLICIT_RULE_DENY,
                rule_id=strongest.rule_id,
            )

        temporary_reason = self._temporary_reason(snapshot, context)
        if temporary_reason is not None:
            return self._deny(snapshot, operation, phase, temporary_reason)

        builtin_reason = self._builtin_sensitive_reason(snapshot, context)
        if builtin_reason is not None:
            return self._deny(
                snapshot,
                operation,
                phase,
                builtin_reason[0],
                rule_id=builtin_reason[1],
            )

        if matched_allows:
            strongest = min(
                matched_allows,
                key=lambda item: (-item.rule.priority, item.rule_id),
            )
            return self._allow(
                snapshot,
                operation,
                phase,
                PolicyReasonCode.EXPLICIT_RULE_ALLOW,
                rule_id=strongest.rule_id,
            )

        if snapshot.configuration.rules.default_effect is RuleEffect.ALLOW:
            return self._allow(snapshot, operation, phase, PolicyReasonCode.DEFAULT_ALLOW)
        return self._deny(snapshot, operation, phase, PolicyReasonCode.DEFAULT_DENY)

    def _validate_context(
        self,
        snapshot: _EngineSnapshot,
        context: PolicyEvaluationContext,
    ) -> PolicyReasonCode | None:
        if not context.metadata.fields:
            return PolicyReasonCode.SOURCE_UNAVAILABLE
        age = context.evaluated_at - context.metadata.observed_at
        if (
            age < timedelta(0)
            or age.total_seconds() > snapshot.configuration.rules.max_metadata_age_seconds
        ):
            return PolicyReasonCode.STALE_CONTEXT
        for field in context.metadata.fields:
            if not field.provenance:
                return PolicyReasonCode.MALFORMED_CONTEXT
            value = field.value
            if isinstance(value, str) and ("\x00" in value or len(value) > _MAX_METADATA_TEXT):
                return PolicyReasonCode.MALFORMED_CONTEXT
        return None

    def _match_rule(
        self,
        compiled: _CompiledRule,
        snapshot: _EngineSnapshot,
        context: PolicyEvaluationContext,
    ) -> _Match:
        rule = compiled.rule
        matches: list[_Match] = []
        if rule.application is not None:
            matches.append(self._match_text(context.metadata, "application", rule.application))
        if compiled.title_pattern is not None:
            title = self._string_field(context.metadata, "window.title")
            if title is None:
                matches.append(_Match.UNKNOWN)
            elif len(title) > _MAX_METADATA_TEXT or "\x00" in title:
                matches.append(_Match.MALFORMED)
            else:
                matches.append(
                    _Match.MATCH
                    if compiled.title_pattern.search(title) is not None
                    else _Match.NO_MATCH
                )
        if rule.workspace is not None:
            matches.append(self._match_text(context.metadata, "workspace", rule.workspace))
        if compiled.normalized_domain is not None:
            raw_domain = self._string_field(context.metadata, "url.domain")
            if raw_domain is None:
                matches.append(_Match.UNKNOWN)
            else:
                try:
                    domain = _normalize_domain(raw_domain)
                except ValueError:
                    matches.append(_Match.MALFORMED)
                else:
                    if rule.include_subdomains:
                        domain_match = domain == compiled.normalized_domain or domain.endswith(
                            "." + compiled.normalized_domain
                        )
                    else:
                        domain_match = domain == compiled.normalized_domain
                    matches.append(_Match.MATCH if domain_match else _Match.NO_MATCH)
        if rule.full_screen is not None:
            if context.full_screen is None:
                matches.append(_Match.UNKNOWN)
            else:
                matches.append(
                    _Match.MATCH if context.full_screen is rule.full_screen else _Match.NO_MATCH
                )
        if rule.metadata_source is not None:
            source_ids = {
                provenance.source_id
                for field in context.metadata.fields
                for provenance in field.provenance
            }
            if not source_ids:
                matches.append(_Match.UNKNOWN)
            else:
                matches.append(
                    _Match.MATCH if rule.metadata_source in source_ids else _Match.NO_MATCH
                )
        if rule.time_window is not None:
            local_time = (
                context.evaluated_at.astimezone(snapshot.timezone).timetz().replace(tzinfo=None)
            )
            start = rule.time_window.start
            end = rule.time_window.end
            if start < end:
                in_window = start <= local_time < end
            else:
                in_window = local_time >= start or local_time < end
            matches.append(_Match.MATCH if in_window else _Match.NO_MATCH)
        if _Match.MALFORMED in matches:
            return _Match.MALFORMED
        if _Match.NO_MATCH in matches:
            return _Match.NO_MATCH
        if _Match.UNKNOWN in matches:
            return _Match.UNKNOWN
        return _Match.MATCH

    def _temporary_reason(
        self,
        snapshot: _EngineSnapshot,
        context: PolicyEvaluationContext,
    ) -> PolicyReasonCode | None:
        for marker in snapshot.temporary:
            if marker.capture_generation != context.capture_generation:
                continue
            current = self._sensitive_scope_value(marker.scope, context.metadata)
            if current != marker.value:
                continue
            if marker.scope is SensitiveScope.WINDOW:
                return PolicyReasonCode.TEMPORARY_SENSITIVE_WINDOW
            return PolicyReasonCode.TEMPORARY_SENSITIVE_WORKSPACE
        return None

    def _builtin_sensitive_reason(
        self,
        snapshot: _EngineSnapshot,
        context: PolicyEvaluationContext,
    ) -> tuple[PolicyReasonCode, str] | None:
        application = self._string_field(context.metadata, "application")
        normalized_application = application.casefold() if application is not None else None
        if normalized_application in _BUILTIN_SENSITIVE_APPLICATIONS:
            return PolicyReasonCode.SENSITIVE_APPLICATION, "builtin-password-manager"
        if normalized_application in _BUILTIN_LOCK_APPLICATIONS:
            return PolicyReasonCode.SESSION_LOCKED, "builtin-lock-screen"
        if normalized_application in _BUILTIN_AUTH_APPLICATIONS:
            return PolicyReasonCode.SENSITIVE_APPLICATION, "builtin-auth-dialog"

        title = self._string_field(context.metadata, "window.title")
        if title is not None:
            normalized_title = title.casefold()
            if any(token in normalized_title for token in _AUTH_TITLE_TOKENS):
                return PolicyReasonCode.SENSITIVE_TITLE, "builtin-auth-title"

        if application is not None and any(
            normalized_application == configured.casefold()
            for configured in snapshot.configuration.rules.sensitive_applications
        ):
            return PolicyReasonCode.SENSITIVE_APPLICATION, "configured-sensitive-application"

        workspace = self._scalar_field(context.metadata, "workspace")
        if workspace is not None:
            workspace_text = str(workspace).casefold()
            if any(
                workspace_text == configured.casefold()
                for configured in snapshot.configuration.rules.sensitive_workspaces
            ):
                return PolicyReasonCode.SENSITIVE_WORKSPACE, "configured-sensitive-workspace"
        return None

    @staticmethod
    def _remote_authorized(snapshot: _EngineSnapshot) -> bool:
        configuration = snapshot.configuration
        return (
            configuration.profile is PrivacyProfile.LOCAL_FIRST
            and configuration.models.remote_enabled
            and any(provider.enabled for provider in configuration.models.remote_providers)
        )

    @staticmethod
    def _sensitive_scope_value(
        scope: SensitiveScope,
        metadata: ContextMetadata,
    ) -> str | int | None:
        name = "window.id" if scope is SensitiveScope.WINDOW else "workspace"
        value = PolicyEngine._scalar_field(metadata, name)
        if isinstance(value, str | int):
            return value
        return None

    @staticmethod
    def _match_text(metadata: ContextMetadata, field_name: str, expected: str) -> _Match:
        value = PolicyEngine._scalar_field(metadata, field_name)
        if value is None:
            return _Match.UNKNOWN
        text = str(value)
        if "\x00" in text or len(text) > _MAX_METADATA_TEXT:
            return _Match.MALFORMED
        return _Match.MATCH if text.casefold() == expected.casefold() else _Match.NO_MATCH

    @staticmethod
    def _field(metadata: ContextMetadata, name: str) -> ContextField | None:
        return next((field for field in metadata.fields if field.name == name), None)

    @staticmethod
    def _scalar_field(metadata: ContextMetadata, name: str) -> MetadataScalar:
        field = PolicyEngine._field(metadata, name)
        return None if field is None else field.value

    @staticmethod
    def _string_field(metadata: ContextMetadata, name: str) -> str | None:
        value = PolicyEngine._scalar_field(metadata, name)
        return value if isinstance(value, str) else None

    @staticmethod
    def _compile(configuration: LocalRecallConfig) -> tuple[_CompiledRule, ...]:
        compiled: list[_CompiledRule] = []
        for rule in configuration.rules.rules:
            pattern = re.compile(rule.title_pattern) if rule.title_pattern is not None else None
            domain = _normalize_domain(rule.domain) if rule.domain is not None else None
            compiled.append(
                _CompiledRule(
                    rule=rule,
                    rule_id=rule.rule_id or _anonymous_rule_id(rule),
                    title_pattern=pattern,
                    normalized_domain=domain,
                )
            )
        return tuple(compiled)

    @staticmethod
    def _allow(
        snapshot: _EngineSnapshot,
        operation: PolicyOperation,
        phase: PolicyPhase,
        reason: PolicyReasonCode,
        *,
        rule_id: str | None = None,
    ) -> PolicyDecision:
        return PolicyDecision(
            operation=operation,
            phase=phase,
            allowed=True,
            certain=True,
            reason_code=reason,
            rule_id=rule_id,
            policy_revision=snapshot.revision,
            policy_generation=snapshot.generation,
        )

    @staticmethod
    def _deny(
        snapshot: _EngineSnapshot,
        operation: PolicyOperation,
        phase: PolicyPhase,
        reason: PolicyReasonCode,
        *,
        certain: bool = True,
        rule_id: str | None = None,
    ) -> PolicyDecision:
        return PolicyDecision(
            operation=operation,
            phase=phase,
            allowed=False,
            certain=certain,
            reason_code=reason,
            rule_id=rule_id,
            policy_revision=snapshot.revision,
            policy_generation=snapshot.generation,
        )


def _anonymous_rule_id(rule: CaptureRule) -> str:
    payload = rule.model_dump_json(exclude={"rule_id"}, exclude_none=True)
    digest = hashlib.blake2s(payload.encode("utf-8"), digest_size=10).hexdigest()
    return f"rule-{digest}"


def _normalize_domain(value: str) -> str:
    normalized = value.strip().casefold()
    if normalized.endswith("."):
        normalized = normalized[:-1]
    if not normalized or len(normalized) > 253:
        raise ValueError("policy domain is invalid")
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        labels = normalized.split(".")
        if len(labels) < 2:
            raise ValueError("policy domain is invalid") from None
        for label in labels:
            if not 1 <= len(label) <= 63:
                raise ValueError("policy domain is invalid") from None
            if label[0] == "-" or label[-1] == "-":
                raise ValueError("policy domain is invalid") from None
            if not all(
                character.isascii() and (character.isalnum() or character == "-")
                for character in label
            ):
                raise ValueError("policy domain is invalid") from None
        return normalized
    return address.compressed.casefold()
