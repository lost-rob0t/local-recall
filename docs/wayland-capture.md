# Wayland capture through desktop portals

**Status:** v0.1 portal-screenshot implementation for issue #35.
**Authority:** lifecycle, policy, and session-safety gates remain authoritative; this backend only acquires pixels after an `ApprovedCaptureRequest` exists.

## Capture path

The Wayland stack is composed as:

`WaylandPortalCaptureBackend -> PortalGateway -> BusctlPortalGateway -> FixedBusctlPortalRunner`

The portal gateway invokes only two fixed `busctl` invocations against the user session bus:

- `busctl --user call org.freedesktop.portal.Desktop /org/freedesktop/portal/desktop org.freedesktop.portal.Screenshot Screenshot "sa{sv}" "" 1 "handle_token" "s" <token>`
- `busctl --user monitor --json=short --match "type='signal',interface='org.freedesktop.portal.Request',member='Response',path='<request-path>'"`

No shell is used, arguments are fixed, and only the token varies. Every invocation is bounded in time and output size.

## Authorization model

- Authorization is **per capture**: each frame requires a fresh portal `Screenshot` request that the user can grant or deny through the desktop portal dialog.
- A denied or cancelled dialog maps to `portal-permission-denied` and produces no frame.
- `WaylandPortalCaptureBackend.revoke()` immediately fails all in-flight captures with `portal-permission-revoked`, discards their gateway results, and blocks all subsequent captures until the process is reconfigured. This is the programmatic counterpart to closing the portal dialog.
- There are **no persistent portal sessions**: the backend never keeps a long-lived portal grant across captures, and `status()` always reports `persistent_sessions=false`.
- There is **no fallback** to compositor internals, privileged helpers, or third-party screenshot tools on Wayland. If the portal is unavailable or lacks screenshot capability, capture fails with `portal-unavailable` or `portal-screenshot-unavailable`.

## Failure and privacy invariants

- Screenshot payloads are decoded in memory by a bounded PNG codec (`capture/png.py`); pixels never touch disk from Local Recall.
- The portal hands back a temporary `file://` URI. The gateway reads it fail-closed (`O_NOFOLLOW`, must be a regular file owned by the current user, bounded size), **unlinks the file immediately after reading**, and fails the capture with `portal-cleanup-failed` if the deletion fails for any other reason, because leaving portal-written pixels on disk is unacceptable.
- Every portal failure surfaces as a content-free `PortalError` reason code; portal messages, bus traffic, and pixel bytes never appear in errors, logs, or status.
- Frames carry provenance `backend_id="wayland-portal"`, `backend_revision="portal-screenshot-v1"`, and never claim an Xorg backend.

## Wayland-specific limitations

These are reported by `session_resolution_status` (the `wayland` status block) and enforced by the implementation:

- `window-metadata-unavailable`: no compositor window metadata is collected on Wayland; frames carry empty context metadata. Window-region cropping (trusted `window.x/y/width/height`) is therefore disabled; the full output is captured.
- `persistent-sessions-not-used`: no PipeWire screen-stream session is kept open; every frame is an independent authorized request.
- `screencast-streams-not-supported`: the PipeWire screen-cast flow is not implemented in v0.1; only the screenshot flow exists.
- `region-cropping-unavailable`: only full-output captures are produced.

## Session resolution

`SessionResolver` accepts an optional `wayland_portal_probe`. On a Wayland session:

- probe healthy: `recording_supported=true`, `capture_backend_id="wayland-portal"`, reason `ready`; metadata sources may be empty because portal capture does not depend on compositor metadata.
- probe unhealthy or timing out: `recording_supported=false`, reason `portal-unavailable`.
- probe not configured: reason `unsupported-session` (unchanged behavior; Wayland never silently selects the Xorg backend).

On Xorg sessions the portal probe is ignored and Xorg resolution is unchanged.

## Environment requirements

- A running `xdg-desktop-portal` with a Screenshot-capable backend for the session (`xdg-desktop-portal-wlr` on wlroots compositors such as sway; `xdg-desktop-portal-gnome`/`-gtk` on GNOME; KWin's portal on KDE).
- `busctl` (systemd) on `PATH`; the user session bus at `$DBUS_SESSION_BUS_ADDRESS` or `$XDG_RUNTIME_DIR/bus`.
- PipeWire is not required for the screenshot flow.

## Testing

CI and unit suites exercise the full behavior through fake portal gateways and scripted busctl runners (contract, unit, integration, and security suites), including revocation races, oversized/malformed payloads, symlinked or foreign-owned portal files, and traversal URIs. A real compositor + real portal validation on one wlroots compositor and one desktop environment remains a human verification step; see `rage/issue-35-wayland-portal-capture.org`.
