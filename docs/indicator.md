# Recording status indicator

Local Recall exposes a daemon-authoritative, content-free recording indicator model for desktop status surfaces.

## Authority boundary

The indicator is a client and view only. It does not own lifecycle, capture, policy, storage, retrieval, or transport authorization. Every visible state comes from a fresh typed `STATUS` request through `DaemonClient`.

A previously visible `recording` state is discarded immediately when the next status request is unavailable, malformed, timed out, or faulted. Desktop events may eventually be used as wakeups, but they are never authoritative state.

Issue #29 owns the authenticated local IPC server and transport. The indicator does not add an unauthenticated socket or TCP listener while that work is pending.

## States

The closed display states are:

- `off`
- `paused`
- `recording`
- `privacy`
- `locked`
- `overloaded`
- `faulted`
- `unavailable`

`recording` is rendered only when the current daemon response succeeds with lifecycle state `recording`. Privacy mode is supplied explicitly by daemon status and is not inferred from a generic paused state.

## Operational details

The optional status payload may contain only bounded operational identifiers for the active capture backend and metadata source plus an aware timestamp for the last successful capture. Identifiers accept ASCII letters, digits, `-`, `_`, and `.` only and are limited to 128 characters.

Screenshot pixels, OCR text, window titles, command lines, usernames, provider payloads, storage paths, exception text, and arbitrary daemon failure reasons never enter the indicator models.

## Controls

`IndicatorSurface` provides one-action `stop`, `privacy_on`, and `privacy_off` operations. Each operation sends the existing typed daemon command and then performs a fresh status request. The UI never mutates itself optimistically.

A successful `stop` is accepted by the shared CLI service boundary only when the daemon authoritatively reports lifecycle state `off`. The daemon-side stop barrier and hard capture-generation invalidation remain lifecycle/IPC responsibilities rather than UI responsibilities.

## Qtile integration

`QtileIndicatorAdapter` is dependency-light and can be wired into a polling text widget. Its methods return only closed status text such as `LR:REC`, `LR:OFF`, `LR:PRIV`, and `LR:?`.

Conceptually, a Qtile integration supplies the authenticated `DaemonClient`, constructs one `IndicatorController` and `IndicatorSurface`, then uses:

```python
adapter.poll_text(now=current_time())
adapter.stop(now=current_time())
adapter.privacy_on(now=current_time())
adapter.privacy_off(now=current_time())
```

The Qtile wrapper should bind polling to `poll_text` and mouse/key callbacks to the control methods. It must not inspect capture internals or shell out to parse CLI output.

## Generic Linux tray integration

`StatusNotifierItemAdapter` maps the same authoritative surface to StatusNotifierItem-compatible presentation fields and one-action controls. Recording requests `NeedsAttention`, off/unavailable are `Passive`, and the remaining states are `Active`.

The presentation contains a fixed title, a closed icon name, and a content-free tooltip with state, validated backend/source identifiers, and last-capture time. A desktop-specific D-Bus host may publish these fields; the optional session-bus transport remains outside the core authority model so importing Local Recall does not require a GUI or D-Bus dependency.

## Restart behavior

Daemon or desktop restart is handled by pull-authoritative recovery. A failed status request produces `unavailable` and clears backend/source/last-capture details. A later successful request reconstructs the visible state from daemon truth; stale recording state is never retained across reconnect.
