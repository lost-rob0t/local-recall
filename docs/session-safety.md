# Session lock and idle safety

Issue #18 adds an orthogonal session-safety authority on top of the lifecycle gate from #7 and the policy engine from #17. It does not create another capture state machine.

## Lock authority

Linux/Xorg uses the target `org.freedesktop.login1.Session` on the local system D-Bus. The source resolves only the configured session ID through `GetSession`, validates the returned object path, and queries the session `LockedHint` property with bounded calls. `busctl` is invoked directly with a fixed executable and argument vector; no shell is used. The source never accepts another session object's events.

`LockedHint=true` is locked. `LockedHint=false` is the only observation that can establish unlocked state. A login1 `Lock` signal is treated immediately as a conservative lock transition. An `Unlock` signal is only an unlock request and therefore changes the normalized state to unknown until a fresh `LockedHint=false` query confirms the state. Malformed replies, permission failures, timeouts, disconnects, session disappearance, and unknown state all fail closed. Reconnect clears the cached object path and resolves/query the current session again before capture can resume.

At startup the safety preflight runs before the lifecycle can enter recording. A daemon that starts while the desktop is already locked starts paused; unknown startup state is also paused. There is no transient capture window.

## Generation and race model

A lock or automatic idle pause calls the existing lifecycle gate's generation invalidation path. The active generation is cancelled, a fresh paused generation is allocated, queued/in-flight work is cancelled and drained, and volatile buffers for the old generation are cleared. The policy engine's lock state changes its independent policy generation as well.

The persistence gate's existing commit lock is the linearization point. If a lock transition wins that ordering before persistence, the old frame is stale and cannot persist. If persistence already owns the commit section, it is ordered before the lock. Pipeline stages re-check the lifecycle generation after processing, so old-generation OCR, redaction, encryption, indexing, summarization, and provider-bound work cannot advance after invalidation.

A successful unlock or active-idle observation does not resurrect previously authorized work. New capture requires fresh lifecycle and policy authorization.

## Idle sources and threshold

Idle handling is separate from lock handling and is disabled by default to preserve prior profile behavior. When enabled, normalized ActivityWatch metadata is preferred. The ActivityWatch adapter remains the raw AFK parsing boundary and exposes `idle` plus the opt-in normalized `idle.seconds` duration. The idle subsystem never consumes an ActivityWatch payload directly.

On Xorg the local fallback is `xprintidle`, which reads the X Screen Saver extension's time since last input. It is called without a shell, with a fixed executable, bounded output, a deadline, and a seven-day maximum value. Missing or malformed fallback support produces unknown idle state, never a lock-state override. `xprintidle` is included in the Nix development environment.

Source resolution is deterministic: ActivityWatch is preferred when current; the Xorg duration source is the fallback. If current sources conflict, idle wins conservatively. Stale observations are ignored as current evidence. Missing idle support does not weaken lock-screen blocking.

`capture.idle` settings are immutable validated configuration:

- `enabled`: default `false`;
- `pause_capture`: default `true`;
- `threshold_seconds`: `> 0` and at most 24 hours;
- `resume_behavior`: `immediate`, `active-grace`, or `manual`;
- `active_grace_seconds`: required only by `active-grace`, at most five minutes;
- `max_observation_age_seconds`: positive and at most five minutes.

Duration comparisons use `>=`: exactly the configured threshold is idle. Active-grace timing uses a monotonic clock. A restrictive reload may invalidate authorization immediately. A more permissive reload can release a pause but can never revive an old generation.

## Precedence

| Lock | Idle | Result |
| --- | --- | --- |
| locked | active/idle/unknown | blocked: lock |
| unknown | active/idle/unknown | blocked: lock unknown |
| unlocked | idle | blocked: idle when enabled |
| unlocked | active | lifecycle eligible |
| unlocked | unknown | lifecycle eligible unless an existing idle pause is latched conservatively |

Manual pause and privacy mode remain distinct. Unlock/activity does not override a manual pause, and privacy mode prevents automatic idle resume.

## Audit and status

Lifecycle transitions already pass through the closed audit schema for `session_locked`, `session_unlocked`, `idle`, and `active`. The session-safety API additionally exposes typed content-free events/status containing only normalized control state, fixed source IDs/revisions, generation, timestamps, threshold, health, and fixed failure codes. Raw D-Bus replies, ActivityWatch payloads, usernames, titles, domains, command lines, OCR, and pixels are never part of these objects.

## Limitations

This issue does not implement Wayland portal capture. Correct `LockedHint` reporting requires the desktop/session locker to cooperate with logind; if it does not, Local Recall remains fail closed rather than assuming unlocked. The Xorg fallback requires the X Screen Saver extension and `xprintidle`; its absence disables idle fallback only, never lock protection.
