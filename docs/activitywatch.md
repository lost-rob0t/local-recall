# ActivityWatch metadata

Local Recall can use an existing local ActivityWatch server as an optional metadata source. This adapter enriches the capture that Local Recall is already evaluating; it does **not** copy, synchronize, export, or persist the ActivityWatch database.

ActivityWatch's API is treated as version-unstable and untrusted input. Local Recall validates bucket metadata and event schemas at its own boundary and keeps its own privacy, exclusion, redaction, routing, encryption, and persistence policies authoritative.

## Configuration

ActivityWatch is conservative by default:

```toml
[metadata]
enabled_sources = ["activitywatch", "xorg-generic"]
window_titles_enabled = false

[metadata.activitywatch]
endpoint = "http://127.0.0.1:5600"
connect_timeout_seconds = 0.25
request_timeout_seconds = 0.75
correlation_window_seconds = 2.0
url_mode = "disabled"
```

`metadata.activitywatch.endpoint` must be a bare loopback HTTP origin. The only accepted host forms are `127.0.0.1`, `localhost`, and `::1`. Credentials, HTTPS, remote addresses, query strings, fragments, and non-root base paths are rejected. ActivityWatch requests use a direct loopback socket; HTTP proxy environment variables are not consumed and redirects are never followed.

`url_mode` is a closed setting:

- `disabled` is the default and does not query browser buckets.
- `domain-only` may query compatible current-tab buckets, but emits only the validated hostname as `url.domain`.

There is no full-URL mode. In domain-only mode, URL paths, query strings, fragments, embedded credentials, and IP-literal hosts are not emitted. Window titles are independently controlled by `metadata.window_titles_enabled` and remain disabled by default.

These fields are additive schema-version-1 settings. Existing schema-version-1 configuration keeps the conservative defaults without migration.

## Bucket discovery

The adapter asks the local server for bucket metadata and recognizes compatible event types equivalent to:

- `currentwindow`;
- `afkstatus`;
- `web.tab.current` when domain collection is enabled.

Bucket IDs are opaque. Local Recall never assumes an ID derived from a username or hostname and does not trust a bucket merely because its ID resembles an ActivityWatch convention.

At most 32 buckets are inspected. Malformed or unknown bucket metadata is ignored. Compatible buckets are grouped by event type and host. A bucket matching the server's reported local hostname is preferred. If no local-host bucket exists and candidates span several hosts, the adapter fails that source as ambiguous rather than combining unrelated devices. Multiple candidates for the same selected host are bounded and evaluated deterministically.

The source health probe reads only server and bucket metadata. It does not query event history. A listening port alone therefore does not make the source healthy: at least one compatible, usable bucket capability must be discoverable.

## Correlation semantics

For each needed bucket type, Local Recall asks only for events in a small interval around the capture instant. The default tolerance is two seconds on each side of the capture time, and the configured tolerance may not exceed five seconds. The transport rejects event-query spans above ten seconds and limits each bucket response to at most 16 events.

This answers one question: *which ActivityWatch event corresponds to this capture?* It is not a history query.

Event timestamps must be timezone-aware. Durations must be finite, non-negative, and no longer than 24 hours. A zero-duration heartbeat can match the exact capture instant. Events whose interval overlaps the capture instant have highest relevance; otherwise an immediately adjacent event may match only within the configured tolerance. Stale events are rejected. Semantic duplicates are collapsed, out-of-order responses are normalized, and ties prefer the newest event start deterministically.

An old long-running event is not considered current merely because its duration is large: it must still satisfy the bounded query and explicit overlap/correlation rules.

## Normalized fields

Compatible data is mapped into the existing Local Recall metadata vocabulary:

| ActivityWatch concept | Local Recall field | Default |
| --- | --- | --- |
| active application | `application` | enabled |
| active window title | `window.title` | disabled |
| AFK status | `idle` (`bool`) | enabled |
| current browser hostname | `url.domain` | disabled |

Application strings are normalized deterministically. AFK input accepts only the closed ActivityWatch statuses `afk` and `not-afk`, which become `True` and `False`; arbitrary status strings are discarded. Every retained field carries `activitywatch` provenance, bounded confidence, the observation time, and the adapter revision.

## Failure and fallback

ActivityWatch is optional. Connection refusal, timeout, invalid JSON, malformed schemas, oversized responses, ambiguous hosts, missing compatible buckets, or no correlated event produce fixed sanitized reason codes. Raw payloads, titles, applications, URLs, domains, and other ActivityWatch values are not included in exception text, representations, health/status JSON, or audit payloads.

If ActivityWatch is unavailable or degraded, the resolver can continue with other configured metadata sources such as Qtile or generic Xorg. An ActivityWatch failure does not by itself fault the desktop capture session when another valid metadata strategy is available.

## Privacy boundary

ActivityWatch being local does not make its stored content trusted or pre-sanitized. Values accepted by this adapter remain in-memory metadata and continue through Local Recall's normal capture policy and deterministic redaction stage before encryption or persistence.

The adapter has no storage API, model-provider API, or audit-content write path. It cannot persist plaintext or route values to a remote model. Later provider routing remains governed by Local Recall's provider policy. ActivityWatch's own retention or privacy configuration does not weaken any Local Recall invariant.

## Transport and resource bounds

The loopback client enforces fixed request paths, connection and request deadlines, a 16 KiB response-header ceiling, bounded response bodies, a maximum bucket count, bounded candidate counts, a maximum of 16 events per bucket query, bounded string lengths, the correlation-window ceiling, and cancellation-safe socket closure. Redirects, chunked responses, duplicate `Content-Length`, invalid lengths, truncated bodies, duplicate JSON keys, and wrong JSON shapes fail closed.

No export endpoint, full-bucket download, bulk synchronization, or unbounded ActivityWatch Query API call is used.

## Sanitized troubleshooting

Troubleshooting output should be limited to facts such as:

- whether the loopback server is available;
- which compatible source *types* were discovered;
- which normalized field names could be emitted;
- a field count;
- a fixed reason code.

Do not print actual application names, titles, URLs, domains, AFK history, raw bucket payloads, or event bodies while diagnosing ActivityWatch support.
