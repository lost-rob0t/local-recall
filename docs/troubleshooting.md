# Troubleshooting and safe diagnostic collection

**Status:** v0.1. Everything in this guide avoids exposing captured content: the diagnostic bundle is content-free by construction, and you should never paste raw logs, records, or previews into bug reports.

## Common failures

### `local-recall status` prints `daemon-unavailable` (exit 3)

- The daemon session is not running, or the authenticated IPC credentials are missing/expired.
- Fix: start the daemon session (NixOS: `systemctl --user start local-recall`), then retry. The CLI never falls back to unauthenticated or remote paths.

### `key-locked` / `encryption-unavailable` in `health`

- The OS keyring is locked or the record key is missing. Persistence is refused fail-closed until key access is restored.
- Unlock the keyring (or restore the key provider); `health` must show `encryption-keys: healthy` before capture resumes. Key rotation and destruction procedures are in [encryption](encryption.md).

### `portal-permission-denied` / `portal-unavailable` (Wayland)

- The desktop portal dialog was denied, or no Screenshot-capable portal backend is installed (`xdg-desktop-portal-wlr` on wlroots, `-gnome`/`-kde` on desktop environments).
- Capture stays off; every frame requires a fresh authorization. See [Wayland capture](wayland-capture.md).

### `disk-quota-exhausted`

- Free space fell below the configured floor. Capture is capture-blocking until space is reclaimed.
- Retention sweeps (bounded, audited) reclaim space; the report records reclaimed bytes only.

### `index-behind-storage` / semantic index failures

- Derived index state diverged from the storage catalog. Capture and persistence continue; answers may be incomplete.
- Repair: run the `index-rebuild` safe-repair operation (restartable, audited, never destructive). See [health](health.md).

### Storage corruption

- Corrupt records are quarantined automatically; `health` reports degraded storage with opaque counts. Forward-only recovery (`recover()`) is part of the audited `orphan-cleanup` repair; quarantined data is never silently deleted.

## Emergency stop

- CLI: `local-recall stop` (urgent priority), or `local-recall privacy-on` for immediate privacy mode.
- UI: the emergency-stop button is keyboard-accessible (`accesskey="s"`, or press `Escape` in the browser window). Stop and privacy mode halt new persistence within the documented bound (see [E2E budgets](e2e.md)).

## Safe diagnostic collection

1. Run the diagnostic bundle: it contains versions, closed health-check results with fixed reason codes, and opaque counts only — no paths, hostnames, usernames, window titles, or message text. Bundles reject free-form content-shaped tokens by construction and are covered by secret scanning.
2. Attach the bundle JSON to a bug report. Do **not** attach raw audit logs, storage directories, IPC dumps, or screenshots; the audit log records only sanitized counts, enums, and digests, and storage contents are ciphertext — but raw logs from your own debugging may contain more.
3. Reproduce parser bugs deterministically with the documented fuzz seeds ([testing](testing.md)) — the failing example and seed are sufficient, no payload needed.
4. Redaction limitations: deterministic redaction covers known patterns, encoded secrets, and high-entropy strings; it cannot detect secrets it has no pattern for, and image-region masking covers only policy-approved sensitive regions. Sensitive applications and workspaces should be excluded through capture policy rather than trusted to redaction (see [redaction](redaction.md) and [policy](policy.md)).
