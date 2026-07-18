# ADR-0008: Implement explicit key-provider routing and envelope schema 2

- **Status:** Accepted
- **Date:** 2026-07-18
- **Decision owners:** Local Recall project
- **Implements:** ADR-0004
- **Related:** #10, `INV-002`, `INV-003`, `INV-004`

## Context

ADR-0004 selected per-artifact XChaCha20-Poly1305 envelope encryption but deferred the concrete encoding, provider behavior, and rotation mechanism to issue #10.

## Decision

Use envelope schema version 2 with canonical JSON associated data, a strict six-frame multipart encoding, random per-record DEKs, and provider-authenticated DEK wrapping.

Support three built-in wrapping strategies:

1. operating-system keyring;
2. Argon2id-protected encrypted local key store;
3. explicitly configured GPG recipient fallback.

Fallback is attempted only for an unavailable primary provider. Locked, invalid, revoked, or authentication-failing providers never trigger fallback.

KEK rotation rewraps the DEK while preserving record ciphertext, nonce, and associated data. Provider key IDs and versions are non-secret envelope metadata; key material never enters application configuration or logs.

## Consequences

- Storage and backups remain opaque to record plaintext.
- Tampering with content or bound metadata is detected.
- Recovery depends on retaining the configured keyring entry, encrypted store plus passphrase, or GPG private key.
- Python provides only best-effort key-buffer wiping.
- GPG availability does not widen policy because selection is explicit and health checked.
