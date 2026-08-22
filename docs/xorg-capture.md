# Xorg capture backend

**Status:** v0.1 Xorg implementation for issue #19.  
**Authority:** lifecycle, policy, and session-safety gates remain authoritative; this backend only acquires pixels after an `ApprovedCaptureRequest` exists.

## Capture path

The production stack is composed as:

`XorgCaptureBackend -> XwdSnapshotReader -> FixedXwdNativeRunner -> BoundedNativeCommandExecutor`

The native runner executes only:

- `xwd -root -silent`
- `xrandr --listmonitors`

Executable paths are resolved outside the capture hot path and supplied as absolute paths to the composition boundary. No shell is used and captured metadata is never interpolated into command arguments.

`xwd` writes the root-window dump to stdout. Local Recall reads that stream directly into bounded memory, validates the XWD header and payload, and converts the supported TrueColor layout to packed RGB8. The capture implementation has no screenshot filename, temporary-file, image-encoder, or plaintext persistence path.

## Monitor and focused-window behavior

Local Recall reads `xrandr --listmonitors` before and after the root capture. A topology change fails the capture with the fixed `display-changed` reason instead of attaching stale monitor provenance.

The captured frame records:

- root geometry;
- selected capture region;
- monitor rectangles and scale provenance;
- capture timestamp;
- backend ID and revision.

Focused-window mode does not perform a second X11 drawable capture. It crops the already-authorized root image in memory only when all required geometry fields were allowed by policy and originate exclusively from trusted normalized metadata adapters. Missing, untrusted, malformed, or out-of-root geometry falls back to the full authorized desktop image.

## Privacy and failure behavior

The backend does not decide whether recording is allowed. Existing lifecycle, capture-policy, lock, idle, privacy-mode, and generation authorities issue or invalidate capture authorization.

Hard properties:

- an unapproved request cannot invoke pixel capture;
- expired deadlines fail before helper execution;
- helper timeout, caller cancellation, or live output overflow terminates the child process;
- stdout and stderr are bounded;
- `LD_PRELOAD`, proxy variables, and unrelated environment values are not passed to capture helpers;
- private native output, display values, executable paths, and pixel bytes are excluded from public errors;
- monitor topology changes, display loss, malformed XWD data, unsupported layouts, and size violations fail closed without constructing a frame;
- returned frames preserve the approved lifecycle generation;
- raw pipeline ingress requires that producer generation explicitly as `expected_generation` and compares it with the current capture permit before accepting any bytes;
- a frame produced under generation N therefore cannot be relabelled as N+1 after lock, privacy, stop, fault, or other generation invalidation; rejected stale buffers are scrubbed before the exception escapes;
- no backend failure can create a plaintext screenshot artifact through Local Recall.

## Supported XWD subset

v0.1 accepts bounded XWD version 7 `ZPixmap` TrueColor captures with 16-, 24-, or 32-bit source pixels and explicit non-overlapping RGB masks. The parser validates dimensions, stride, byte order, header length, color-table bounds, pixel length, and root geometry before normalization.

Unsupported or malformed layouts return the sanitized `capture-format-invalid` failure rather than attempting a permissive decode.

## Runtime dependencies and limitations

The Xorg backend requires working `xwd` and `xrandr` executables from the active Xorg environment. Their absolute paths are supplied to `build_xorg_capture_backend`; the capture boundary itself does not perform shell lookup.

This backend is Xorg-only. Wayland capture remains a separate portal-backed implementation issue and must not silently fall back to Xorg or privileged compositor internals.

The backend does not persist, OCR, summarize, index, or call model providers. Raw captured pixels continue through the existing bounded in-memory pipeline and deterministic redaction/encryption boundaries.
