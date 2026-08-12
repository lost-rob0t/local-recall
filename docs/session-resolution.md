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

- `xorg-generic`: baseline application and window-title capability on a confirmed Xorg session;
- `qtile`: application, window-title, and workspace capability after a Qtile-specific health check;
- `activitywatch`: application, activity, and idle capability after a local ActivityWatch health check.

Issues #14, #15, and #16 implement the corresponding metadata collectors and concrete health adapters. Issue #13 only defines detection, probing, selection, and composition.

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
