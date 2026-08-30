# Zara visual-context integration

**Status:** v0.1 for issue #60 (companion Zara issue tracked on the Zara side).
**Authority:** Local Recall is the sole authority for capture selection, lifecycle state, redaction, retrieval, provider routing, and audit. Zara is an owner-authenticated client: it never reads screenshot files or storage and never retains image data.

## Protocol versioning

- Wire contract version: `zara-visual-context-v1` (`vision.context.PROTOCOL_VERSION`).
- The version rides both in the typed request (`protocol_version`) and in the IPC routing frame (`visual_context_version`). A mismatch is rejected with a sanitized `unsupported-visual-context-version` before any content-bearing parse.
- Versioning rules: the version increments only when the closed request/response fields change in a breaking way; additive optional response fields keep the same version until the next breaking change. Responses always echo the current version so clients can detect skew.

## Transport

The request/response ride the existing owner-only `ipc://` boundary — the same session-token authentication pattern as every other CLI command (`SessionToken` frames, constant-time comparison, three frames: routing/authentication/payload). There is **no TCP listener** and no second port.

`vision/ipc.py` provides:

- `VisualContextRequestCodec(token, capabilities)` — `encode(request) -> (routing, auth, payload)` and `decode(frames, now)`; decode performs authentication before any content parse, enforces routing/payload size limits (`payload-too-large`), rejects malformed JSON (`invalid-payload`), unknown versions, and expired deadlines (`deadline-expired`).
- `VisualContextIpcHandler(service, codec)` — decodes, runs `VisualContextService.explain`, and returns the typed response; Zara's client renders `response.to_json()`.

## Contract

```text
ExplainVisualContextRequest
  protocol_version       "zara-visual-context-v1"
  request_id             opaque client-chosen id (<=128 chars, no path characters)
  selector               current | recent | bounded_window
  start / end            required only for bounded_window (start < end)
  maximum_records        1..8 (minimum working set)
  deadline               timezone-aware; expired requests fail closed
  remote_authorization   absent | explicit

ExplainVisualContextResponse
  request_id
  outcome                explained | denied | unavailable
  explanation            bounded text (only for explained)
  selected_start/end     actual selected window (only for explained)
  record_count
  provider_class         local | authorized_remote (only for explained)
  confidence_summary     mean provider confidence (only for explained)
  reason_code            sanitized code for denied/unavailable
```

Stable rejection reason codes: `privacy-mode`, `session-locked`, `capture-not-active`, `lifecycle-unhealthy`, `query-policy-denied`, `missing-context`, `deadline-expired`, `cancelled`, `remote-not-authorized`, `working-set-unavailable`, `vision-unavailable`, `vision-failed`.

## Behavior guarantees

- **Local default**: analysis runs through the configured local vision provider; `provider_class` is `local`. Remote analysis requires BOTH `remote_authorization=explicit` on the request AND a per-query `EgressAuthorization` object routed through the `EgressGate`; otherwise the request is denied with `remote-not-authorized`. There is never a silent local→remote fallback.
- **Minimum working set**: only `maximum_records` records within the selector window are decrypted; everything is memory-only and dropped when the call returns.
- **Refusals**: privacy mode, session lock, non-active capture, unhealthy critical dependencies, query-policy denial, missing context, expired deadlines, and cancellations (`VisualContextService.cancel(request_id)`) all return stable sanitized outcomes; nothing is partially explained.
- **No capture interference**: the service only observes lifecycle state; it has no API that can start, resume, or alter capture.
- **Audit**: acceptance and outcome events use the `visual_context_request` IPC audit action with fixed reason codes and no attributes; request ids, explanation text, prompts, and content never enter audit logs. Debug parameters are no-ops.
- **Response hygiene**: the response carries explanation text and opaque indicators only — never screenshot bytes, raw OCR, window titles, command lines, usernames, secrets, provider prompts, or storage paths. Tests seed all of these and assert their absence from responses and audit.

## Client fixtures (Zara implements against these without importing internals)

Request (payload frame JSON):

```json
{"deadline": "2026-08-30T12:00:05+00:00", "end": null, "maximum_records": 3,
 "selector": "recent", "start": null}
```

Routing frame JSON:

```json
{"protocol_version": "ipc-v1", "visual_context_version": "zara-visual-context-v1",
 "request_id": "c0ffee00-0000-4000-8000-00000000aa01", "remote_authorization": "absent"}
```

Explained response JSON (payload of `to_json()`):

```json
{"confidence_summary": 0.8, "explanation": "editing: emacs with a document open",
 "outcome": "explained", "provider_class": "local", "protocol_version": "zara-visual-context-v1",
 "reason_code": null, "record_count": 1,
 "selected_end": "2026-08-30T11:55:00+00:00", "selected_start": "2026-08-30T11:55:00+00:00",
 "request_id": "c0ffee00-0000-4000-8000-00000000aa01"}
```

Denied response JSON:

```json
{"confidence_summary": null, "explanation": null, "outcome": "denied",
 "provider_class": null, "protocol_version": "zara-visual-context-v1",
 "reason_code": "privacy-mode", "record_count": 0, "request_id": "...",
 "selected_end": null, "selected_start": null}
```
