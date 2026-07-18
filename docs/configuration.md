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
max_queue_items = 32
change_threshold = 0.02

[metadata]
enabled_sources = ["generic-xorg"]

[redaction]
enabled = true
deterministic_required = true
fail_on_uncertain = true
model_assistance_enabled = false
policy_revision = "builtin-v1"

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
provider_id = "keyring"
algorithm = "xchacha20-poly1305"

[encryption.key_reference]
provider_id = "keyring"
reference = "local-recall-record-key"

[storage]
backend_id = "sqlite-blobs"
root_directory = "~/.local/share/local-recall"
```

The `reference` fields identify entries managed by a key provider. They are not secret values. Effective-configuration inspection replaces reference names with `<configured>`.

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

| Variable | Field |
|---|---|
| `LOCAL_RECALL_PROFILE` | `profile` |
| `LOCAL_RECALL_CAPTURE_ENABLED` | `capture.enabled` |
| `LOCAL_RECALL_CAPTURE_CADENCE_SECONDS` | `capture.cadence_seconds` |
| `LOCAL_RECALL_CAPTURE_SCREENSHOTS_ENABLED` | `capture.screenshots_enabled` |
| `LOCAL_RECALL_RETENTION_MAX_AGE_DAYS` | `retention.max_age_days` |
| `LOCAL_RECALL_RETENTION_MAX_BYTES` | `retention.max_bytes` |
| `LOCAL_RECALL_MODELS_GENERATION_PROVIDER` | `models.generation_provider` |
| `LOCAL_RECALL_MODELS_EMBEDDING_PROVIDER` | `models.embedding_provider` |
| `LOCAL_RECALL_MODELS_REMOTE_ENABLED` | `models.remote_enabled` |
| `LOCAL_RECALL_ENCRYPTION_PROVIDER` | `encryption.provider_id` |
| `LOCAL_RECALL_STORAGE_BACKEND` | `storage.backend_id` |

Unknown variables beginning with `LOCAL_RECALL_` reject the configuration. Secret and credential values have no environment override. `LOCAL_RECALL_CONFIG` may identify the configuration path and is not treated as a field override.

## Atomic reload and failure behavior

A reload follows this order:

1. Read the candidate without changing the active snapshot.
2. Parse TOML.
3. Migrate the schema in memory.
4. Apply allowlisted non-secret environment overrides.
5. Validate the entire effective configuration.
6. Compute a deterministic revision digest.
7. Atomically replace the active immutable snapshot.

If any step fails, the candidate is never partially visible. The manager atomically installs the built-in capture-disabled safe snapshot. This deliberately stops an active capture configuration rather than continuing under a stale configuration after an invalid reload.

Error messages contain field locations and validation reasons but omit rejected input values.

## Schema migration

The loader requires `schema_version`.

### Version 0 to version 1

The migration is deterministic:

- `privacy_mode` becomes `profile`;
- `recording_enabled` becomes `capture.enabled`;
- `interval_seconds` becomes `capture.cadence_seconds`.

If old and new names both exist, migration rejects the file as ambiguous. Migrated configuration is then validated against the complete version 1 security rules. A migrated file that enabled capture without encryption or storage therefore fails closed.

Versions newer than the runtime supports are rejected. Migrations never silently discard unknown fields; the final model forbids extras.
