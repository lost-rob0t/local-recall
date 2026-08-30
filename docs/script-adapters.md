# Allowlisted script-based metadata adapters

Issue #34 lets users feed metadata from their own scripts without creating a command-injection surface.

## Configuration and validation

Each adapter is configured with a closed typed config: a unique name, an absolute script path, a fixed argument template (at most 8 non-empty arguments), a bounded timeout, a bounded output size, schema version, an optional SHA-256 pin, and an environment-variable allowlist. Configuration itself rejects relative paths, malformed argument templates, and malformed pins.

Before every run the script is re-validated without following symlinks: it must be a regular file owned by the current user with owner-only permissions (no group/other bits). When a pin is configured, a modified script is disabled until the pin is re-approved. Construction validates eagerly and fails closed.

## Execution sandbox

Scripts run through `create_subprocess_exec` with a strict argument vector — there is no shell, no interpolation, and no captured desktop value can enter the command line. The child environment contains only the allowlisted variables; the working directory is a fresh private temporary directory. Standard input is closed and stderr is discarded. Timeout or output-limit violations kill the process and raise a sanitized failure.

## Output contract

The script must print one JSON object with exactly `{"application", "schema_version", "workspace"}`, schema version 1, and bounded string-or-null values. Anything else — malformed JSON, wrong version, unexpected keys, wrong types, empty or oversized values — is rejected with a sanitized `ScriptAdapterFailure`. Callers degrade to other metadata sources; metadata failures never widen capture permissions (policy defaults remain deny-by-default for sensitive contexts).

Values flow into the standard `ContextField` path with provenance (`source_id` = adapter name, per-run adapter revision derived from the script digest), so redaction and policy checks downstream treat script output exactly like every other metadata source.

## Security coverage

Tests cover: group/other-writable rejection, symlink rejection, foreign-owner rejection pattern, pin-mismatch disablement, malformed/versioned/oversized JSON rejection, timeout kill, output-limit kill, fixed argv (spied process arguments contain only the script path and configured template), hostile environment exclusion with allowlist passthrough, and a sanitized working directory.
