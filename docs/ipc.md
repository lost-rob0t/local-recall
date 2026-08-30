# Authenticated local daemon IPC

Local Recall exposes control, query, and diagnostic operations through an owner-only local IPC boundary. The v0.1 transport is ZeroMQ `ROUTER`/`DEALER` over a pathname Unix-domain socket. It does not bind TCP, loopback TCP, an abstract Unix socket, or another network listener by default.

## Endpoint and runtime directory

The endpoint lives below the current user's validated XDG runtime directory, under a Local Recall-owned service directory. Startup fails closed when the runtime directory is missing, relative, a symlink, owned by another UID, or more permissive than mode `0700`.

The socket node is created as mode `0600`. After bind, the daemon verifies that the path is a socket owned by the expected UID with exactly that mode. A stale endpoint is removed only when `lstat` proves it is a same-owner socket; a regular file, symlink, or wrong-owner object is never replaced automatically.

When libzmq exposes `IPC_FILTER_UID`, the listener also restricts accepted IPC peers to the daemon UID. This is defense in depth rather than the protocol authentication authority.

## Authentication and capabilities

Each daemon start creates a fresh random session token in the private runtime directory. The token file is owner-only mode `0600`, bounded to the project-defined token length, read without following symlinks, and validated for owner, type, mode, and stable inode/device identity. Restart rotates the token, invalidating clients that retained an earlier session credential.

Requests use three protocol frames after the ZeroMQ routing identity:

1. content-free routing metadata;
2. the session-authentication token;
3. the bounded typed request payload.

Authentication is checked before content payload parsing. The closed command set is mapped to explicit capabilities:

- **control**: lifecycle/status/privacy commands;
- **query**: ask, timeline, search, and record preview;
- **diagnostic**: provider, health, and storage-stat operations;
- **delete**: destructive selective-deletion operations (issue #30).

A routing frame cannot upgrade a command into another capability, and priority metadata is checked against the command's canonical priority.

Filesystem permissions, UID filtering, and the session token jointly prevent another local UID from using the supported IPC path. They do not claim strong isolation from arbitrary malicious code already running as the same UID; that residual risk remains part of the threat model.

## Bounds and scheduling

The protocol routing frame is bounded, and the request payload is limited to 128 KiB. The ROUTER also sets libzmq `ZMQ_MAXMSGSIZE` to the same 128 KiB value before bind, so the native transport does not retain libzmq's unlimited inbound-message default and then rely solely on Python decoding to reject oversized input.

Normal requests use a bounded pending lane and finite worker pool. STOP/privacy requests use a separately bounded urgent lane with reserved execution capacity, so blocked or saturated query work cannot starve emergency controls. Clients derive finite send/receive timeouts from the typed request deadline and use zero linger on shutdown. Responses are independently bounded and request IDs must match.

## Failure and audit behavior

Malformed framing, authentication failure, authorization failure, overload, handler failure, response mismatch, transport timeout, and unavailable-daemon conditions use fixed sanitized outcomes. They do not include endpoint paths, usernames, tokens, query text, answer text, OCR, window titles, screenshots, provider prompts, or exception content.

Authenticated requests emit content-free IPC audit metadata containing only authorization outcome, one capability class, and whether the request used the urgent lane. Destructive deletion requests additionally emit a separate sanitized `deletion_request` audit event carrying only the closed scope class, the selected record count, and the outcome; scope text, application or workspace names, and record contents never enter the audit stream. Authentication failures and malformed multipart messages emit rejected events with unknown capability rather than parsing attacker-controlled content merely to improve the audit label. Malformed requests are dropped without handler dispatch, and a later valid request can continue to use the server.

Audit failure never makes a malformed packet executable. For a well-formed authenticated request, an audit failure prevents dispatch and returns a sanitized internal failure.

## Client boundaries

The CLI constructs its default client from the validated XDG runtime location and communicates through the shared `DaemonClient` contract. The recording-status indicator depends on the same service boundary rather than importing lifecycle, capture, storage, or provider internals. This keeps presentation code from becoming a second daemon authority.

A later loopback transport can be added deliberately behind the same typed client/server contracts, but it must define its own authentication, authorization, origin, TLS, and egress rules. There is no automatic TCP fallback in v0.1.

## Verification

The issue #29 test suite covers private runtime paths, rotating credentials, protocol authentication before payload parsing, capability and priority validation, socket ownership/mode, request and native message bounds, reserved urgent capacity, rejected-auth audit evidence, malformed multipart survival/auditing, response correlation, and CLI/indicator use of the authenticated client boundary. Synthetic fixtures only are used; tests do not inspect real desktop content.
