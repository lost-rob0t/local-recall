# CLI controls and query contract

Local Recall exposes a narrow command-line client for lifecycle control, privacy control, queries, and sanitized operational diagnostics. The CLI is a client of the daemon; it is not a second lifecycle, retrieval, storage, or provider authority.

## Command surface

Lifecycle and privacy controls:

```text
local-recall start
local-recall pause
local-recall resume
local-recall stop
local-recall status
local-recall privacy-on
local-recall privacy-off
```

Query and inspection commands:

```text
local-recall ask "What was I doing Saturday?"
local-recall timeline [--start ISO-8601 --end ISO-8601] [--application NAME] [--json]
local-recall search QUERY [--start ISO-8601 --end ISO-8601] [--json]
local-recall preview RECORD_ID [--image] [--json]
local-recall providers [--json]
local-recall health [--json]
local-recall storage stats [--json]
```

Destructive deletion commands (issue #30) always require one explicit closed scope:

```text
local-recall delete --record-id UUID [--record-id UUID ...] [--json]
local-recall delete --cluster CLUSTER_ID [--json]
local-recall delete --application NAME --start ISO-8601 --end ISO-8601 [--json]
local-recall delete --start ISO-8601 --end ISO-8601 [--json]
```

Deletion goes through the authenticated IPC boundary, requires the daemon-side
`delete` capability, emits a sanitized audit event, and cannot be undone. See
`timeline.md` for scope semantics.

Configuration validation is local and does not contact the daemon:

```text
local-recall config validate PATH
```

Explicit time bounds must be timezone-aware and supplied as a start/end pair. `ask` and `search` require non-empty query text. Query text is payload content and is excluded from routing metadata and object representations.

## Authoritative state

Lifecycle success is accepted only when the daemon returns an authoritative lifecycle state. A content-free success response is treated as an internal failure. `stop` is stricter: it returns success only when the daemon confirms `off`, meaning capture and the bounded stop barrier have quiesced. The CLI never treats message delivery itself as proof that a control action completed.

`stop`, `privacy-on`, and `privacy-off` carry the `urgent-control` priority class. Ordinary lifecycle/status operations carry `control`; query and diagnostic operations carry `query`. The client tags priority but does not schedule requests. Server-side ordering and authorization belong to the daemon API.

## IPC ownership

The architecture defines the eventual CLI/query transport as owner-only ZeroMQ `ROUTER/DEALER` over `ipc://`, with authentication, bounded messages, deadlines, and no TCP listener by default. That authenticated server and transport binding are owned by issue #29.

Until that server is implemented, the default CLI daemon client fails closed with the stable `daemon-unavailable` outcome. Tests inject a typed `DaemonClient` implementation to validate the complete client-side contract without introducing an unauthenticated interim socket.

The CLI/client modules deliberately do not import capture, lifecycle, storage, retrieval, answering, provider, or routing implementations. Those authorities stay inside the daemon.

## Output and privacy

Machine-readable output uses closed typed response schemas. Cited query results contain only explicitly requested answer text plus opaque record IDs and capture timestamps. Diagnostic output is bounded and sanitized.

Status, errors, completion, routing metadata, and object representations must not expose captured text, raw OCR, window titles, command lines, secrets, provider payloads, or storage paths. Shell completion is static and never queries daemon history or captured data.

## Exit codes

| Exit | Meaning |
|---:|---|
| `0` | Confirmed success |
| `2` | Invalid request or CLI input |
| `3` | Daemon unavailable, overloaded, or timed out |
| `4` | Unauthorized or key/session locked |
| `5` | Daemon fault, invalid success envelope, or internal/client failure |
| `130` | Cancelled |

Exit codes reflect typed outcomes rather than arbitrary exception text.
