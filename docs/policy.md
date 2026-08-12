# Capture policy

Local Recall's capture policy is an authoritative security boundary. It decides whether desktop context may be captured or processed; it does not merely attach advisory labels.

A policy **allow** never bypasses lifecycle state, redaction, encryption, retention, persistence checks, or provider-routing controls.

## Operations

Policy decisions are independent for:

- `screenshot`
- `metadata`
- `ocr`
- `indexing`
- `summarization`
- `remote-provider`

A context may therefore permit metadata while denying pixels, or permit local indexing while denying remote-provider eligibility.

## Phases

### Pre-capture

Pre-capture evaluation uses normalized metadata and runtime state available before pixel acquisition. A deny or uncertain screenshot decision prevents the screenshot action from being invoked.

Examples include privacy mode, lock state, password managers, authentication prompts, configured sensitive workspaces, source-based rules, and domain rules when domain-only metadata is available.

### Post-capture / pre-persistence

Post-capture evaluation is performed again before persistence. A deny or uncertain result rejects the frame. A policy revision, privacy-mode transition, lock transition, or capture-generation transition also invalidates an earlier authorization.

The enforcement boundary deliberately rechecks authorization immediately before the side effect. This prevents queued or in-flight work from relying forever on an old allow.

### Downstream gates

OCR, indexing, summarization, and remote-provider eligibility are evaluated separately. Remote eligibility is only an eligibility decision: the policy engine never invokes a remote provider itself.

## Precedence

Precedence is deterministic and security-first:

1. unhealthy policy state
2. manual privacy mode
3. locked session
4. explicit configured deny rules
5. temporary sensitive current-window/current-workspace markers
6. built-in or configured sensitive-context denies
7. explicit configured allow rules
8. profile/default effect

Configured deny rules always beat configured allow rules even when an allow has a numerically higher priority. Within multiple matching rules of the same effect, higher numeric priority wins; ties are resolved by stable rule identifier. Configuration order and filesystem order do not affect the result.

A weak allow cannot override privacy mode, lock state, an explicit deny, a temporary sensitive marker, or a built-in safety deny.

## Built-in sensitive contexts

The built-in list is intentionally narrow. It covers known password-manager classes, common lock-screen applications, common authentication agents, and a small set of authentication-title indicators.

The engine does **not** treat every terminal as sensitive. Additional applications and workspaces such as a dedicated pentesting workspace should be configured explicitly.

Built-in decisions use stable identifiers such as `builtin-password-manager` and never copy the matching application or title into a decision.

## Manual privacy mode

Manual privacy mode is a hard runtime deny. Entering privacy mode increments the policy generation and invalidates earlier authorizations. New screenshot, OCR, indexing, summarization, and remote-provider work is denied.

Metadata is a separate operation because enough normalized metadata may be required to establish policy context. Interfaces must still honor the configured metadata/privacy semantics rather than interpreting metadata permission as pixel permission.

Privacy mode is not a UI-only flag.

## Temporary sensitive context

The policy control boundary can temporarily mark either:

- the current window, identified by normalized `window.id`; or
- the current workspace/group, identified by normalized `workspace`.

Markers have an explicit TTL from one second through 24 hours, are bound to the current capture generation, take effect immediately, and invalidate earlier authorizations. Expiry and explicit clearing are deterministic. Markers do not survive into a new capture generation.

A later CLI or desktop control can call this typed boundary without duplicating policy logic.

## Rule configuration

Rules are immutable Pydantic models with `extra='forbid'`. The schema supports:

- stable `rule_id`
- `enabled`
- numeric `priority`
- `effect` (`allow` or `deny`)
- one or more `operations`
- exact application matching
- bounded title-pattern matching
- exact workspace matching
- domain matching
- optional subdomain matching
- full-screen state
- metadata source/provenance
- timezone-aware time windows
- stable reason code

Rules must have at least one selector. Unknown fields, duplicate rule identifiers, empty operation sets, malformed domains, unsupported timezones, invalid time windows, and unsafe title patterns are rejected at validated configuration load.

The new fields are additive with safe defaults, so schema version 1 remains valid; no persistent migration is required.

## Application, title, and workspace matching

Application and workspace selectors are case-insensitive exact matches against normalized Local Recall metadata.

Title patterns are compiled during configuration loading and capped at 256 characters. Python regular-expression constructs associated with unbounded or complex evaluation are restricted: malformed expressions, lookaround/inline constructs other than leading `(?i)`, alternation, backreferences, nested repetition, and excessive unbounded repetition are rejected. Metadata text is capped at 4096 characters before hot-path matching. These bounds prevent attacker-controlled pathological expressions or desktop strings from turning policy evaluation into unbounded work.

## Domain matching

Policy consumes canonical `url.domain` metadata only. It never reconstructs or persists a full URL.

Domains are case-normalized and a single trailing root dot is accepted. Malformed domains are rejected. IP literals are matched exactly.

For a rule on `example.com`:

- exact mode matches `example.com` only;
- `include_subdomains=true` also matches `a.example.com`;
- neither mode matches `notexample.com`.

Subdomain matching uses a label boundary (`.`), not a raw string suffix.

## Metadata-source conditions

Source rules inspect normalized provenance source identifiers such as `xorg-generic`, `qtile`, or `activitywatch`. The policy engine does not consume adapter-specific payloads.

A source-specific deny cannot be bypassed by falling back to that same source. A rule that requires unavailable policy-relevant context produces an uncertain deny for capture-sensitive operations.

## Missing, stale, malformed, and conflicting context

Capture-sensitive operations fail closed when policy context is unavailable, stale, malformed, or required by a rule but missing. Exceptions do not become implicit allows.

Stable sanitized reason codes include:

- `source-unavailable`
- `required-context-missing`
- `malformed-context`
- `stale-context`
- `default-deny`
- `privacy-mode`
- `session-locked`
- `remote-not-authorized`

The engine accepts only already-normalized `ContextMetadata`; adapter composition remains responsible for resolving source conflicts before policy evaluation. If composition cannot produce trustworthy normalized context, the resulting absence/uncertainty fails closed.

## Time windows and timezone

Rules use an explicit IANA timezone from policy configuration; they do not depend implicitly on the host timezone. Evaluation uses aware timestamps and converts them to configured local wall time.

Both ordinary windows and windows crossing midnight are supported. Equal start/end times are rejected as ambiguous. DST transitions are deterministic because each evaluation starts with an absolute aware timestamp.

## Policy revision and stale work

Each loaded policy has an immutable revision string plus an in-memory policy generation. The generation changes on privacy-mode transitions, lock transitions, temporary-sensitive changes/expiry, and policy replacement.

An authorization is current only when its policy revision, policy generation, and capture generation still match current state. A restrictive reload therefore cannot make queued work authorized under an older revision newly valid.

Configuration validation remains atomic at the configuration boundary. The existing configuration manager fails malformed reloads to the project's safe default instead of falling through to a permissive configuration.

## Remote-provider eligibility

`remote-provider` is an independent operation. It remains denied unless the active profile is `local-first`, remote models are enabled, and an enabled remote provider has passed the existing validated configuration invariants.

A local-provider failure does not modify policy state and cannot turn a remote deny into an allow.

## Audit and status privacy

Policy decisions contain only control data: operation, phase, allow/deny, certainty, reason code, optional rule identifier, policy revision, and policy generation. They cannot carry screenshots, OCR text, titles, URLs, or matched substrings.

Status contains only revision, generation, enabled-rule count, privacy/lock state, health, and a sanitized error code.

Effective configuration inspection replaces application, title-pattern, workspace, domain, and metadata-source selector values with `<configured>` markers. Existing audit records accept only a closed set of safe fields and therefore cannot store a raw title, domain, command line, username, OCR payload, or matched secret.

## Limits and privacy caveats

Policy evaluation is bounded to at most 256 configured rules, 256 characters per title pattern, and 4096 characters per evaluated metadata string. These are validation/security limits, not tuning suggestions.

Policy reduces capture risk; it cannot guarantee that every sensitive context is recognizable before pixels exist. Unknown or missing policy-relevant context therefore fails closed for capture-sensitive operations. Users should still use privacy mode or temporary sensitive markers for novel or intentionally private workflows.

Again: a policy allow does not bypass redaction, encryption, lifecycle checks, retention, storage authorization, or provider-routing controls.
