# Timeline and privacy-management UI

**Status:** v0.1 loopback UI server for issue #36.
**Authority:** every user-visible action maps onto the closed authenticated IPC command set (`cli_contract.CliCommand`); the UI server holds no authority of its own and stores nothing.

## Architecture

`src/local_recall/timeline/ui.py` implements `TimelineUiServer`:

- **Loopback only**: binds `127.0.0.1` on an ephemeral port; any other host is rejected at construction. The server exists only after an explicit `start()` call (explicit enablement) and stops on `close()`.
- **Authenticated session**: `start()` mints a per-session bearer token (`secrets.token_urlsafe`). Every `/api` request must present `Authorization: Bearer <token>` (constant-time comparison); anything else is `401`.
- **Daemon boundary**: the server talks to the daemon exclusively through the existing `DaemonClient` port (`cli_service.execute_command`), so the UI inherits the authenticated IPC request path, deadlines, and sanitized responses. No new daemon commands are introduced.
- **Static asset policy**: the single HTML shell is embedded in the module — no third-party assets, fonts, frameworks, CDNs, analytics, or telemetry. The shell contains no `http://`/`https://` URLs at all (asserted by tests).
- **Stdlib only**: `http.server` + `http.client` in tests; no new dependencies.

## Endpoints

| endpoint | maps to | notes |
| --- | --- | --- |
| `GET /api/status` | `status` | capture state, privacy mode, backend |
| `GET /api/timeline?start&end` | `timeline` | bounded time window required |
| `GET /api/search?q=` | `search` | |
| `POST /api/answer` | `ask` | local-only unless remote processing is explicitly confirmed per answer |
| `GET /api/preview/<record-id>?target=text\|image` | `preview-record` | decrypt-on-demand |
| `POST /api/delete` | `delete-records` | requires `confirm: true`; without it the server refuses and echoes the exact scope |
| `POST /api/stop` | `stop` | emergency stop (keyboard accessible) |
| `POST /api/privacy-on` / `privacy-off` | `privacy-on` / `privacy-off` | |
| `POST /api/session/close` | — | clears credentials and shuts the server down |

## Privacy invariants (tested)

- **No browser caching**: every response — including the HTML shell and previews — carries `Cache-Control: no-store` and `Pragma: no-cache`, so history/cache inspection reveals no captured content beyond the active session.
- **Decrypt-on-demand previews**: preview payloads are rendered straight through to the authenticated client response; the server retains zero preview payloads (`cached_previews() == 0`) and never writes to disk.
- **Destructive scope**: `/api/delete` without `confirm: true` performs no daemon call and returns the exact scope (`record_ids`, `scope_kind`) that would be deleted; with confirmation the daemon's own scope resolution and audit still apply.
- **Emergency stop**: the stop button is keyboard-accessible (`accesskey="s"` plus an `Escape` keydown handler in the shell) and maps to the urgent `stop` command.
- **Session end**: `/api/session/close` and inactivity expiry (`session_timeout_seconds`) both clear the session token; subsequent requests are `401` and the server stops.
- **Fail-closed rendering**: daemon failures surface as fixed reason codes (`503`/`400`/`403` by outcome) with no daemon internals.

## Testing

- `tests/unit/timeline/test_ui_server.py` — auth, command mapping, preview, delete confirmation, stop/privacy mapping, session close/expiry, daemon failure mapping;
- `tests/security/test_ui_privacy.py` — no-store headers on every surface, plaintext-preview non-retention, no external URLs in the asset, keyboard-accessible stop, loopback-only binding, credential clearing on close/expiry.

The UI requires an explicitly enabled daemon session at runtime (`_default_client_factory` fails closed to `daemon-unavailable` until authenticated IPC is configured), so the UI is fully functional with external networking disabled.
