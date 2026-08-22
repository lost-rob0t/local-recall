# Configuration

Local Recall uses one versioned, validated configuration model for capture, metadata, redaction, retention, models, encryption, and storage. The current schema version is `1`.

Configuration is parsed completely before it becomes active. Unknown fields, unsupported schema versions, invalid regular expressions, unsafe profile combinations, and incomplete capture security settings are rejected.

## Safe default

The built-in default is equivalent to:

```toml
schema_version = 1
profile = "privacy-strict"

[capture]
enabled = false
```

Capture is disabled. Remote providers are disabled. Capture rules default to deny. No metadata source is enabled. No encryption key or storage destination is selected.

Starting the daemon with no explicit capture enablement therefore records nothing.

## Privacy profiles

### `privacy-strict`

- Remote providers are forbidden.
- Capture rules must default to deny.
- Model-assisted redaction is forbidden.
- Deterministic redaction and reject-on-uncertainty remain mandatory before capture can start.

### `local-only`

- Remote providers are forbidden.
- Local generation and embedding providers may be selected.
- Capture still requires explicit enablement plus complete metadata, redaction, encryption, key-reference, and storage settings.

### `local-first`

- Local providers remain the default.
- Remote routing remains disabled unless `models.remote_enabled = true`.
- At least one remote provider must then be individually enabled and reference credentials through a key provider.
- Plaintext credentials are not configuration fields.

## Complete local-only example

```toml
schema_version = 1
profile = "local-only"

[capture]
enabled = true
cadence_seconds = 15.0
screenshots_enabled = true
raw_queue_items = 1
max_queue_items = 32
overload_policy = "drop-newest"
change_threshold = 0.02

[metadata]
enabled_sources = ["xorg-generic"]
window_titles_enabled = false

[ocr]
provider_id = "tesseract-local"
executable = "tesseract"
languages = ["eng"]
timeout_seconds = 10.0
max_input_bytes = 67108864

[redaction]
enabled = true
deterministic_required = true
fail_on_uncertain = true
model_assistance_enabled = false
policy_revision = "builtin-v1"
low_confidence_threshold = 0.6

[redaction.entropy]
enabled = true
min_length = 20
min_bits_per_character = 3.5
hex_min_length = 32
max_token_length = 512

[rules]
default_effect = "deny"

[[rules.rules]]
effect = "allow"
application = "emacs"
reason_code = "development-editor"

[[rules.rules]]
effect = "deny"
title_pattern = "(?i)(password|private key|authorization)"
reason_code = "sensitive-title"

[retention]
max_age_days = 30
max_bytes = 21474836480
max_records = 250000

[models]
generation_provider = "ollama"
embedding_provider = "ollama"
remote_enabled = false

[encryption]
provider_id = "os-keyring"
algorithm = "xchacha20-poly1305-ietf"

[encryption.key_reference]
provider_id = "os-keyring"
reference = "local-recall-record-key"

[storage]
backend_id = "sqlite-blobs"
root_directory = "~/.local/share/local-recall"
```

The `reference` fields identify entries managed by a key provider. They are not secret values. Effective-configuration inspection replaces reference names with `<configured>`.

### Generic Xorg metadata

`xorg-generic` is the built-in EWMH active-window source. Window-title collection is
independently controlled by `metadata.window_titles_enabled` and defaults to `false`.
When disabled, the source does not request `_NET_WM_NAME` or `WM_NAME` and never emits
`window.title`. Enabling titles can improve policy decisions, but titles frequently contain
document names, URLs, account names, or other sensitive content. Collected titles remain
in-memory and still pass through deterministic metadata redaction before encryption or
persistence.

This is an additive schema-version-1 setting. Existing version-1 files retain the conservative
default without a migration.

### Qtile metadata

`qtile` is the built-in Qtile/Xorg metadata source. Put it before `xorg-generic` when Qtile-owned
workspace, layout, and screen values should win composition ties:

```toml
[metadata]
enabled_sources = ["qtile", "xorg-generic"]
window_titles_enabled = false
```

The Qtile adapter reuses `metadata.window_titles_enabled`; no command, function, expression,
module, display, or socket path is configurable. Health requires a successful read-only Qtile IPC
status call. If Qtile is unavailable, the resolver can select the configured generic Xorg source.
Collected values remain in memory and enter the existing deterministic metadata-redaction stage
before encryption or persistence. See [desktop session and metadata strategy resolution](session-resolution.md#qtile-collection)
for fields, confidence, bounded retries, command limits, and platform constraints.

### Explicit GPG fallback

GPG fallback is disabled by default and is never inferred from provider availability. To enable it, configure every fallback field explicitly:

```toml
[encryption]
provider_id = "os-keyring"
algorithm = "xchacha20-poly1305-ietf"
fallback_provider_id = "gpg"
gpg_recipient = "configured-recipient"
gpg_executable = "gpg"
gpg_timeout_seconds = 10.0
```

`fallback_provider_id = "gpg"` requires `gpg_recipient`. A recipient without an explicit GPG fallback is rejected, and the primary and fallback provider IDs must differ. The recipient is hidden from effective-configuration inspection. GPG has no environment-variable override because recipient selection is security-sensitive configuration.

## Adaptive capture and pipeline bounds

Adaptive capture is composed directly from the validated `[capture]` settings. `cadence_seconds`
sets the base interval and `change_threshold` sets the maximum 64-bit perceptual-hash Hamming
fraction that may be coalesced as a near duplicate. Active-window/workspace changes use a fixed
250 ms debounce so rapid focus churn replaces one bounded pending trigger rather than creating an
event queue.

The adaptive layer never grants capture permission and owns no bulk queue. It runs only after the
existing lifecycle/policy boundary has produced an approved capture request. A due frame is
fingerprinted before OCR/model work; a near duplicate in the same capture generation,
configuration revision, policy revision, and normalized application/workspace/window context is
coalesced and not admitted downstream. Any of those privacy-context changes force a fresh
observation even when the pixels are identical.

The bounded in-memory pipeline reads these capture settings:

- `raw_queue_items` controls the raw `inproc://` edge and defaults to `1`;
- `max_queue_items` controls each later stage edge and defaults to `32`;
- `overload_policy` is `drop-newest` or `coalesce-latest`.

Both queue limits are validated in the range 1–256. `coalesce-latest` permits at most one additional raw item in memory; it does not create a general-purpose queue. When the existing pipeline reports a dropped or coalesced submission, adaptive cadence backs off by a bounded multiplier; accepted submissions decay it toward the configured base cadence. No second queue or pressure metric is introduced. These fields are additive version-1 settings, so older version-1 files retain safe defaults without migration.

## OCR and redaction

The v0.1 OCR provider is fixed to `tesseract-local`. The configured executable must resolve to a binary named `tesseract`; language identifiers, input size, and timeout are validated. OCR uses standard input/output and does not require a temporary image file.

Deterministic redaction is mandatory before encryption or persistence. The policy covers provider tokens, authorization headers, private keys, credentials and connection strings, email/user identity fields, configurable patterns, and measured high-entropy values. OCR below `low_confidence_threshold` is masked and replaced in full. Any invalid OCR region or policy failure rejects the record.

Custom patterns are declared as `[[redaction.custom_patterns]]` with a safe identifier and regular expression. Allowlists are declared as `[[redaction.allowlists]]`; each entry names exactly one built-in detector ID or `custom:<pattern-id>` and contains at most sixteen exact values. Unknown targets are rejected. Effective-configuration inspection hides exact values, and runtime audit decisions contain a SHA-256 digest rather than the value.

Model assistance may classify only after deterministic filtering and cannot be the sole redaction control. `privacy-strict` forbids model-assisted redaction entirely.

## Capture rules

A rule must select at least one of:

- `application`;
- `title_pattern`;
- `workspace`;
- `metadata_source`.

Multiple selectors in one rule are an AND condition. Rules may allow or deny. Title patterns must compile as regular expressions during configuration validation. Rule evaluation order and conflict handling are implemented by the capture-policy issue; this schema only establishes the validated contract.

## Capture-start requirements

When `capture.enabled = true`, validation requires all of the following:

- at least one metadata source;
- redaction enabled;
- deterministic redaction required;
- reject-on-uncertainty enabled;
- an encryption provider;
- an encryption key reference;
- a storage backend;
- a storage root directory.

A missing requirement rejects the configuration before capture can start.

## Environment overrides

Only the following non-secret overrides are accepted:
