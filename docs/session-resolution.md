# Desktop session and metadata strategy resolution

Issue #13 defines how Local Recall identifies the active desktop session and chooses metadata strategies before capture can start.

## Security boundary

Session resolution is a fail-closed startup decision. It does not capture pixels, collect window content, call model providers, or persist desktop data.

The resolver accepts a normalized environment snapshot and a fixed registry of reviewed metadata probes. It never dynamically imports a configured source, executes a source identifier, or stores arbitrary environment values in its result.

## Session detection

`XDG_SESSION_TYPE` is the authoritative protocol hint.

- `x11` or `xorg` requires a non-empty `DISPLAY` and rejects contradictory Wayland evidence.
- `wayland` requires a non-empty `WAYLAND_DISPLAY`. An additional `DISPLAY` is allowed because XWayland may be active.
- Missing or unknown session types remain `unknown`; Local Recall does not infer Xorg merely because `DISPLAY` exists.
- Missing required display evidence and contradictory evidence remain non-recording.

Desktop-environment detection recognizes only fixed identifiers such as Qtile, GNOME, KDE/Plasma, Sway, XFCE, and COSMIC. Unknown environment strings are discarded rather than copied into status, errors, or audit data.

Wayland capture is not implemented for v0.1. A detected Wayland session is therefore reported accurately but remains non-recording.

## Probe registry

Configured metadata source identifiers are resolved only through the fixed in-process probe registry. Unknown identifiers produce a typed `unknown-source` result; they do not trigger imports, shell commands, executable lookup, or network access.

Each probe reports:

- a fixed source identifier;
- health outcome;
- fixed reason code;
- a closed set of capabilities when healthy.

Every probe has a finite deadline. Timeout, exception, source-identity mismatch, and malformed results are replaced with content-free outcomes. Exception text is never retained.

The built-in probe seams are:

- `xorg-generic`: generic EWMH active-window collection on a confirmed Xorg session;
- `qtile`: application, window-title, and workspace capability after a Qtile-specific health check;
- `activitywatch`: application, activity, and idle capability after a local ActivityWatch health check.

Issue #14 implements the generic Xorg collector and its content-free executable health check.
Issues #15 and #16 implement the Qtile and ActivityWatch collectors. Issue #13 defines
detection, probing, selection, and composition.

## Generic Xorg collection

`GenericXorgMetadataSource` implements the backend-neutral `MetadataSource` port with the fixed
source identifier `xorg-generic`. Xorg types and command output remain inside its adapter
boundary. The source emits the following normalized fields in lexical order when available:

| Field | Value | Availability | Confidence |
|---|---|---|---:|
| `application` | normalized second `WM_CLASS` component, falling back to the first | optional | 0.90 |
| `window.height` | positive client-window height | optional with `xwininfo` | 0.95 |
| `window.id` | validated 32-bit nonzero EWMH window identifier | required | 1.00 |
| `window.title` | `_NET_WM_NAME`, falling back to `WM_NAME` | optional and configuration-gated | 0.90 |
| `window.width` | positive client-window width | optional with `xwininfo` | 0.95 |
| `window.x` | signed root-relative X coordinate | optional with `xwininfo` | 0.95 |
| `window.y` | signed root-relative Y coordinate | optional with `xwininfo` | 0.95 |
| `workspace` | `_NET_WM_DESKTOP` cardinal | optional | 0.90 |

Every emitted field has one `MetadataProvenance` entry with source `xorg-generic`, adapter
revision `ewmh-xprop-v1`, the collection's single timezone-aware observation timestamp, and the
confidence shown above. Missing optional properties are omitted rather than represented through
duplicate aliases or sentinel strings. A non-empty `MetadataRequest.requested_fields` further
minimizes output; an unrequested title is not queried even when title collection is enabled.

Window titles are independently controlled by `metadata.window_titles_enabled` and default to
disabled. When disabled, the adapter excludes `_NET_WM_NAME` and `WM_NAME` from the reviewed
property query and the source cannot emit `window.title`. Titles can contain sensitive document
or account context, so enabling them should be paired with narrow capture rules. They remain raw,
in-memory analyzed-stage metadata until the existing deterministic redaction policy either drops
or approves each field. The source has no storage or network capability.

### Focus and window lifetime policy

Each attempt reads `_NET_ACTIVE_WINDOW`, queries only that validated window, then reads
`_NET_ACTIVE_WINDOW` again. A changed or cleared focus discards the complete attempt; fields from
different windows are never composed. One retry is allowed by default, for two total attempts.
Repeated churn returns the fixed transient reason `focus-changed`.

A window destroyed after focus resolution produces `window-unavailable`; the source may retry
within the same fixed budget and otherwise returns that sanitized reason. A missing or zero
`_NET_ACTIVE_WINDOW` produces `no-active-window`. Malformed/oversized identifiers, responses for
the wrong window, incomplete geometry, malformed properties, timeouts, and unavailable
executables have distinct fixed reason codes. Exceptions and process output are never retained in
the public failure or status types.

### Reviewed command boundary and limits

The production reader deliberately uses the ubiquitous X11 command-line tools instead of adding
a Python X11 binding whose Python 3.14 support and packaging would widen the dependency surface.
It resolves the fixed executable identities `xprop` and optional `xwininfo` once, invokes only
reviewed argument vectors with `create_subprocess_exec`, and never uses a shell. The window
identifier is parsed as a nonzero 32-bit integer and reformatted by the adapter before it can
become an argument.

`xprop` is required for the source health check. `xwininfo` is optional and adds geometry without
making application/title/workspace collection unavailable on minimal installations. Every
invocation has a 0.5-second timeout and a 64-KiB limit on each output stream. The runner kills the
process on timeout or limit violation and discards bounded stdout/stderr after strict parsing.
Status probing checks only executable availability; it never reads root/window properties or
renders active-window content.

Automated tests inject synthetic readers and runners. They do not inspect the developer desktop,
depend on installed X11 tools, or publish raw adapter output. A manual smoke test may report only
success/failure, source ID, normalized field names/count, a fixed reason code, and whether title
collection was enabled.

Generic collection requires an EWMH-compatible Xorg window manager. Non-EWMH managers may report
`no-active-window` or omit optional fields. Wayland collection remains unsupported; an XWayland
`DISPLAY` never causes a Wayland session to be treated as Xorg.

## Selection policy

Configured sources are probed and selected in configuration order. Multiple healthy sources compose; selection is not exclusive.

When at least one specialized source was configured but none is healthy, a registered `xorg-generic` probe is attempted as the final fallback on Xorg. An empty source configuration never enables an implicit fallback.

Recording is supported only when:

1. the session is confirmed Xorg;
2. the Xorg capture strategy is available;
3. at least one metadata source is healthy.

Any other result has no selected capture backend.

## Field conflict policy

Metadata values retain all source provenance. Conflicting values are resolved deterministically:

1. highest field confidence wins;
2. equal confidence uses configured source order;
3. an equal source rank uses the newest observation;
4. the source identifier is the final stable tie-breaker.

All unique provenance records are retained in configured source order. Field output is sorted by normalized field name, and the composed observation time is the latest source observation.

## Sanitized status

`SessionResolution` is the authoritative status payload for this decision. It exposes only:

- detected protocol and recognized desktop identifier;
- fixed detection reason and confidence;
- whether recording is supported;
- selected capture backend identifier;
- ordered selected metadata source identifiers;
- fixed probe outcomes, reason codes, and capabilities;
- final fixed resolution reason.

It contains no display address, socket path, process output, exception text, usernames, window content, titles, commands, or arbitrary environment values. The daemon status command must render this payload without widening it.

## Verification

Unit tests cover:

- Qtile Xorg, generic Xorg, Wayland/XWayland, and missing-evidence paths;
- refusal to guess from `DISPLAY` alone;
- ordered Qtile and ActivityWatch composition;
- generic Xorg fallback;
- unsupported Wayland capture;
- unknown sources without dynamic import;
- bounded probe timeout and sanitized exceptions;
- capability-specific probe behavior;
- confidence, configured-order, timestamp, and stable-name conflict resolution.
