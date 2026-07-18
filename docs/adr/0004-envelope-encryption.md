# ADR-0004: Use per-artifact envelope encryption with XChaCha20-Poly1305

- **Status:** Accepted
- **Date:** 2026-07-17
- **Decision owners:** Local Recall project
- **Related:** #3, `FR-STO-001`–`FR-STO-007`, `FR-LIFE-004`–`FR-LIFE-007`, `INV-002`, `INV-003`, `INV-004`

## Context

Local Recall retains screenshots, OCR-derived text, metadata, embeddings, prompts, summaries, citations, and backups. These artifacts have different lifetimes and deletion scopes. A single long-lived database key would make rotation and cryptographic deletion coarse, while direct GPG encryption of every capture would add subprocess overhead and couple the record format to one key tool.

The encryption design must:

- authenticate content and approved metadata;
- prevent nonce reuse;
- support multiple key providers;
- fail closed when keys are unavailable;
- support rotation and per-record deletion;
- never silently switch to GPG or another provider;
- avoid plaintext staging files.

## Decision

Every content-bearing artifact uses **per-artifact envelope encryption**.

### Content encryption

- Generate a random 256-bit data-encryption key (DEK) for each artifact.
- Encrypt artifact plaintext with XChaCha20-Poly1305 through libsodium bindings.
- Generate a random 192-bit nonce using the operating-system cryptographic random source.
- Authenticate required envelope metadata as associated data.
- Store ciphertext, nonce, wrapped DEK, algorithm/version identifiers, and approved non-secret metadata in a versioned envelope.

XChaCha20-Poly1305 is selected because its extended nonce makes random nonce generation practical at the expected personal-record scale and because mature libsodium implementations are available.

### Key wrapping

A configured `KeyProvider` supplies or unlocks a key-encryption key (KEK). The KEK wraps each DEK using an authenticated construction defined by the envelope version.

The application stores key references and IDs, never the KEK itself in normal configuration.

The initial provider interface supports:

- a Linux Secret Service/keyring-backed provider where available;
- an explicitly configured local protected-keystore provider if implemented;
- an explicitly configured GPG provider.

Provider choice is configuration, not fallback order. If the configured provider is unavailable or locked, persistence fails and capture becomes non-recording.

### GPG behavior

GPG is a key-provider/unlock strategy or explicit export wrapper. It is not silently selected because another provider failed.

Invocations use:

- a fixed executable path or validated executable resolution;
- fixed argument vectors with no shell interpolation;
- bounded input/output and timeout;
- explicit recipient/key fingerprint configuration;
- sanitized errors;
- no plaintext temporary files.

### Associated data

Associated data binds at least:

- envelope version;
- artifact schema version;
- random opaque artifact ID;
- artifact kind;
- non-secret key ID;
- encryption algorithm ID;
- approved coarse catalog bucket and other routing fields used outside the ciphertext.

Changing these fields causes authentication failure.

### Envelope sketch

```text
Envelope {
  magic
  envelope_version
  artifact_schema_version
  artifact_id
  artifact_kind
  algorithm_id
  key_id
  nonce
  wrapped_dek
  associated_data_digest_or_encoding
  ciphertext
}
```

The final binary encoding is specified and test-vectored in issue #10. Parsers use length limits and reject unknown critical fields or unsupported versions.

## Key hierarchy and rotation

- Each artifact has an independent DEK.
- A KEK wraps many DEKs.
- Rotation can rewrap DEKs under a new KEK without decrypting artifact content to disk.
- Full algorithm migration decrypts and re-encrypts one bounded artifact at a time entirely in memory.
- Old key IDs remain resolvable only while records still require them.
- Revoked or unavailable keys produce explicit unreadable/quarantined state, never unauthenticated fallback.

## Cryptographic deletion

Per-artifact DEKs allow deletion to invalidate wrapped keys at record or partition granularity. Physical encrypted blobs, indexes, backups, and catalog references must still follow normal deletion and retention workflows.

The project does not claim that unlink securely erases all historical filesystem or backup copies.

## Nonce management

Nonces are randomly generated per encryption operation. The envelope test suite must:

- verify nonce length and uniqueness across a large deterministic test run;
- inject duplicate/non-random nonce providers and confirm encryption rejects them where detectable;
- confirm retries never reuse a prior `(key, nonce)` pair;
- confirm a failed write does not cause unsafe envelope reuse.

No counter is persisted solely for nonce allocation in v0.1.

## Plaintext and key lifetime

- Encryption receives a `RedactedRecord`, not raw frame or OCR types.
- Plaintext exists only in bounded memory during the operation.
- Buffers are released promptly after encryption.
- Key material is scoped to the minimal operation and never logged, serialized to audit events, or placed in exceptions.
- Best-effort buffer wiping may be used where the backing library supports it.

Python and the operating system cannot guarantee complete zeroization. This remains an explicit residual risk.

## Failure behavior

The following prevent persistence and trigger a critical capture fault:

- missing/locked/invalid configured key provider;
- random-source failure;
- unsupported algorithm or envelope version;
- wrapping or encryption error;
- associated-data construction failure;
- inability to validate the current capture generation;
- storage receiving malformed or unauthenticated envelope bytes.

Decryption authentication failure quarantines the artifact and reports a sanitized integrity error. It never returns partial plaintext.

## Consequences

### Positive

- Tampering with ciphertext or approved routing metadata is detected.
- Per-record DEKs support granular rotation and deletion.
- Key providers remain replaceable.
- GPG remains available without defining the entire storage format.
- Backups can copy opaque envelopes without decrypting them.

### Negative

- Envelope parsing and key rotation add implementation complexity.
- Python cannot provide strict key zeroization.
- Loss of the configured KEK or all valid wrapping keys makes records unrecoverable.
- Key-provider availability is required before capture can persist.

## Alternatives considered

### AES-GCM

Widely supported and acceptable when used correctly, but its shorter nonce makes accidental random nonce collision management less forgiving. XChaCha20-Poly1305 is preferred for this record-oriented format.

### One master key directly encrypting every artifact

Rejected because it weakens granular rotation/deletion and expands consequences of nonce-management mistakes.

### GPG encrypt every record directly

Rejected as the default because subprocess invocation and format coupling would complicate high-frequency capture. GPG remains an explicit key-provider and export option.

### Transparent filesystem or full-disk encryption only

Useful defense in depth but insufficient against copied application data while the filesystem is mounted and unable to enforce application-stage ordering.

## Verification

Issue #10 must begin with failing tests for:

- deterministic format parsing and version rejection;
- known-answer encryption/decryption vectors;
- tamper detection for ciphertext and associated data;
- wrong, missing, locked, and revoked keys;
- nonce generation and retry behavior;
- GPG command construction and explicit selection;
- rotation and DEK rewrapping without plaintext files;
- authentication failure returning no partial plaintext;
- malformed-length and oversized envelope rejection;
- non-zero propagation for every injected cryptographic failure.