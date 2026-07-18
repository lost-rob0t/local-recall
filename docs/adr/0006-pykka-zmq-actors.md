# ADR-0006: Use Pykka actors with ZeroMQ transport

- **Status:** Accepted
- **Date:** 2026-07-17
- **Decision owners:** Local Recall project
- **Supersedes:** ADR-0002
- **Amends:** ADR-0001 toolchain and concurrency sections
- **Related:** #3, `FR-CAP-003`, `FR-CAP-004`, `FR-CAP-008`, `FR-CTL-002`, `INV-001`, `INV-005`, `INV-010`, `INV-011`

## Context

Local Recall needs explicit actor ownership and a transport that can support:

- a fixed hierarchy of Python actors;
- isolation of mutable component state;
- typed request/reply and one-way messages;
- bounded pipeline edges;
- separate control and bulk-data paths;
- owner-only local IPC;
- future process boundaries without introducing a durable broker;
- deterministic overload, timeout, cancellation, and shutdown behavior.

ADR-0002 selected project-built actor-style components over AnyIO memory streams. The project owner requires Pykka for Python actors and ZeroMQ for transport. The earlier decision is therefore superseded before runtime implementation begins.

RabbitMQ is not appropriate here. Local Recall is a single-user daemon, and a persistent broker would add another storage system and another place sensitive payloads could survive. ZeroMQ provides socket patterns without a broker service or durable queue.

## Decision

### Actor framework

All long-running Python components are implemented as subclasses of `pykka.ThreadingActor` or a project-owned base class built on `ThreadingActor`.

Pykka is used for:

- actor lifecycle hooks;
- actor references and request/reply futures;
- actor-owned mutable state;
- actor registration and supervised discovery;
- low-volume lifecycle, health, startup, shutdown, and fault messages.

The project implements the supervisor hierarchy and restart policy. Pykka's registry is not treated as an unrestricted service locator.

### Transport

PyZMQ/ZeroMQ is the data-plane transport between actor boundaries.

- `inproc://` carries raw, redacted, encrypted, index, and query pipeline messages inside the daemon process.
- `ipc://` carries owner-only CLI, status, and query traffic on Linux.
- `tcp://` is disabled by default and is outside the v0.1 local API.
- raw pixels, raw OCR, and unredacted metadata may use `inproc://` only.
- no actor message is persisted by the transport.
- RabbitMQ, Kafka, and filesystem queue fallbacks are prohibited.

### Control plane versus data plane

Pykka actor inboxes carry only bounded, low-volume control and supervision messages. Bulk or sensitive pipeline payloads do not accumulate in a generic Pykka inbox.

ZeroMQ pipeline edges use stage-specific pump actors:

1. a Pykka actor owns one receiving ZeroMQ socket;
2. it receives one message within configured limits;
3. it validates framing and converts the header into a typed domain message;
4. it dispatches synchronously to the target actor with a deadline;
5. it does not consume the next message until the target returns a typed outcome;
6. parallelism requires an explicitly configured, bounded number of pump and worker actors.

This pattern prevents a ZeroMQ receiver from draining a bounded socket into an unbounded Python queue.

### Socket ownership

- One process-owned ZeroMQ context is created and terminated by `TransportSupervisor`.
- Every socket is owned by exactly one actor thread.
- Sockets are never concurrently used by multiple threads.
- Endpoints are generated from fixed roles and opaque IDs, never captured values.
- Bind/connect direction is fixed by the endpoint registry.

### Socket patterns

- `PUSH/PULL` for ordered one-way stage work.
- `ROUTER/DEALER` for addressed commands, replies, IPC, and correlation.
- `PUB/SUB` for sanitized non-authoritative status and audit fanout.

PUB/SUB cannot carry authoritative lifecycle commands because delivery is not guaranteed for disconnected subscribers.

### Framing and serialization

ZeroMQ messages use multipart framing:

1. a versioned JSON header;
2. zero or more bounded binary frames.

The header includes only protocol fields such as message type, opaque job ID, generation, configuration revision, deadline, frame count, declared sizes, and sanitized status.

The following are prohibited:

- pickle;
- arbitrary Python object deserialization;
- generic dictionaries crossing a security boundary without validation;
- content-derived routing identities;
- raw content in endpoint names, headers, logs, or exception messages.

Pydantic validates every external or transport header. Domain constructors validate stage-specific payload invariants after framing checks.

### Bounds and overload

Every socket sets and tests:

- `SNDHWM`;
- `RCVHWM`;
- send/receive deadline behavior;
- `LINGER=0` for fault and shutdown paths;
- `IMMEDIATE=1` where sending to an unavailable peer would be unsafe;
- maximum multipart frame count;
- maximum header size;
- maximum payload size;
- endpoint allowlist.

ZeroMQ high-water marks are not treated as the sole hard bound. Application-level credits, bounded pump counts, bounded actor counts, generation checks, and deadlines are also required.

A saturated send returns a typed overload or timeout result. It cannot:

- return success;
- retry forever;
- create a secondary queue;
- write a temporary file;
- switch to another transport;
- silently drop a lifecycle command.

### Cancellation and stale work

Pykka actor stop and ZeroMQ socket closure accelerate cancellation but cannot preempt every active Python or native-library call.

The authoritative stale-work controls remain:

1. generation invalidation by `LifecycleActor`;
2. generation checks at every security-critical stage;
3. a final generation check immediately before storage commit.

ZeroMQ messages include generation and deadline fields. A delayed, duplicated, or late message is rejected if stale.

### Supervision

`RootSupervisor` starts and monitors:

- `LifecycleActor`;
- `TransportSupervisor`;
- control/status/audit actors;
- capture supervisor;
- query supervisor;
- maintenance supervisor.

Critical actor or transport failure requests a non-recording lifecycle fault before restart. No actor restart authorizes recording. Optional actors use bounded restart budgets.

Unhandled actor failures are sanitized through `on_failure()` and become explicit supervisor events. They are never converted to success replies.

### Blocking work

Pykka `ThreadingActor` gives each actor its own thread. Actor count is fixed and bounded by configuration and hard maximums.

OCR, image processing, storage, provider calls, and ZeroMQ polling run in dedicated stage actors with explicit timeouts. A generic unbounded thread pool is not used.

A future helper process requires another ADR and threat-model update. Raw capture data must not cross a process boundary until that design specifies transport, memory, credentials, crash cleanup, and sandboxing.

## Consequences

### Positive

- Pykka supplies a concrete Python actor model rather than a project-specific imitation.
- Mutable state ownership and lifecycle hooks are explicit.
- ZeroMQ supports `inproc://` and owner-only `ipc://` without an external broker.
- Transport patterns can later support narrowly justified helper processes.
- Control and data traffic are separated.
- High-water marks, deadlines, credits, and pump counts create testable backpressure.
- No persistent broker queue exists.

### Negative

- Pykka's standard runtime is thread based, so actor count must remain small and deliberate.
- Pykka actors do not provide process or memory isolation.
- ZeroMQ socket lifecycle, endpoint ownership, and reconnect behavior add complexity.
- High-water-mark behavior alone is insufficient for a strict application bound.
- Raw data may exist briefly in Python and libzmq memory buffers.
- Pykka actor inboxes are not the bulk-data bound, requiring the pump pattern and contract tests.
- Cancellation cannot forcibly interrupt all native calls; generation checks remain essential.

## Alternatives considered

### AnyIO memory-stream actors

Superseded by owner decision. Structured concurrency remains useful in other Python systems, but it is not the Local Recall actor runtime or message bus.

### Pykka inboxes for every message

Rejected for bulk pipeline data. A generic actor inbox does not provide the required transport scope, IPC capability, socket-level bounds, or separation from high-volume payloads.

### ZeroMQ without Pykka

Rejected because transport alone does not define actor lifecycle, state ownership, registry, supervision structure, or request/reply component contracts.

### RabbitMQ

Rejected. It requires a broker service and introduces persistent queues and operational state that Local Recall does not need.

### Multiprocessing actors

Deferred. It creates a new raw-data process boundary and requires additional sandboxing and cleanup design.

## Verification

Issues #4, #5, #7, and #8 must add tests proving:

- actor classes use the approved Pykka base;
- actor registry cleanup occurs after every test and shutdown;
- only `LifecycleActor` owns state transitions;
- every ZeroMQ socket is owned by one actor thread;
- raw messages use `inproc://` only;
- CLI IPC uses owner-only `ipc://` paths and no default TCP listener;
- HWM, application credits, actor counts, and pump counts are bounded;
- saturation returns non-success and creates no fallback queue or file;
- stop/privacy commands remain deliverable while the data plane is overloaded;
- malformed headers, excess frames, excess sizes, unknown versions, and pickle-like payloads are rejected;
- delayed stale-generation messages cannot commit;
- actor and transport failures fault capture where required;
- context termination and socket closure use finite deadlines and zero linger;
- injected actor, socket, timeout, and protocol failures propagate non-zero through the canonical test command.
