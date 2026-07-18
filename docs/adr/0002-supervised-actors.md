# ADR-0002: Use supervised actors with bounded in-memory mailboxes

- **Status:** Accepted
- **Date:** 2026-07-17
- **Decision owners:** Local Recall project
- **Related:** #3, `FR-CAP-003`, `FR-CAP-004`, `FR-CAP-008`, `INV-001`, `INV-005`, `INV-011`

## Context

Local Recall has concurrent work with different priorities and failure modes:

- lifecycle commands must preempt ordinary work;
- capture triggers may be coalesced;
- raw frames must not accumulate;
- OCR and model calls can be slow;
- stop, lock, privacy, and fault events must cancel in-flight work;
- late work must still be rejected at persistence;
- components need deterministic test seams.

Shared mutable state and ad hoc background tasks would make it difficult to prove who owns lifecycle state, whether cancellation propagated, and whether stale work can persist.

A distributed broker would add persistent queues and more plaintext exposure without solving a v0.1 requirement.

## Decision

The daemon uses an **actor-style concurrency model** implemented with AnyIO structured concurrency.

Each actor:

- owns its mutable state;
- processes immutable typed messages;
- receives messages through one or more bounded AnyIO memory streams;
- runs under a supervisor task group;
- has an explicit startup, healthy, degraded, faulted, and shutdown contract;
- exposes no mutable internal object to another actor;
- emits sanitized events rather than arbitrary exception payloads.

This is an internal architecture, not a public generic actor framework.

## Supervisor hierarchy

`RootSupervisor` owns:

- lifecycle;
- IPC;
- status publishing;
- audit;
- capture supervisor;
- query supervisor;
- maintenance supervisor.

The capture supervisor owns the session, scheduler, metadata, policy, capture, redaction, encryption, storage, indexing, and summary actors.

The query supervisor owns retrieval, provider routing, egress, and answering.

A supervisor may restart an optional actor within a bounded restart budget. A critical actor failure invalidates the current generation and transitions capture to a non-recording state before any restart attempt.

## Lifecycle ownership

Only `LifecycleActor` may mutate lifecycle state or issue capture generations.

Other actors receive immutable lifecycle snapshots and generation tokens. They may request transitions but cannot set state directly.

Cancellation is implemented with both:

1. structured cancellation scopes for prompt work termination; and
2. generation validation at every security-critical stage, including immediately before storage commit.

Cancellation alone is not trusted as the stale-write barrier.

## Mailbox policy

Mailboxes are bounded by configuration and hard maximums.

- Control commands use a dedicated high-priority channel with reserved capacity.
- Capture triggers are coalesced rather than queued indefinitely.
- Raw-frame capacity is intentionally very small.
- Storage overload pauses or faults capture rather than retaining a plaintext backlog.
- Query concurrency is limited per client and globally.
- Maintenance work is lower priority and restartable.

A send that exceeds a deadline must return a typed overload result. It cannot silently enqueue elsewhere or create a temporary file.

## Blocking and CPU-heavy work

Blocking adapters run through AnyIO thread offloading with a dedicated `CapacityLimiter` unless a later ADR justifies a subprocess.

Reasons for not using a process pool by default:

- process serialization creates another raw-data transfer mechanism;
- shared-memory helpers can create named or inspectable objects;
- process crashes are already fail-closed because restart defaults to `off`;
- v0.1 should minimize raw-data copies and process boundaries.

If profiling or native-library reliability later requires a helper process, that boundary requires a new ADR and threat-model update covering transport, memory, credentials, and crash cleanup.

## Error handling

Actors never convert a failed operation into a success message.

A message outcome is one of:

- success with a typed result;
- explicit deny/reject;
- explicit cancellation/stale generation;
- degraded optional capability;
- critical fault.

Unknown exceptions are sanitized and escalated to the actor supervisor. Required test paths inject actor crashes and verify the top-level operation and test command fail.

## Consequences

### Positive

- Clear ownership of lifecycle and component state.
- Bounded work is part of each component contract.
- Structured cancellation and supervisor shutdown are testable.
- Typed messages support stage separation and provenance.
- The architecture matches future actor-oriented extensions without adding a broker.

### Negative

- Logical actors in one process are not memory-isolation boundaries.
- Priority requires separate channels or an explicit dispatcher because a basic stream is FIFO.
- Careless blocking code can still stall an actor.
- Actor protocols add more domain types and contract tests.

## Alternatives considered

### Shared asyncio queues and service objects

Rejected because lifecycle ownership, failure propagation, and bounded behavior would remain informal.

### Thread per component

Rejected because cancellation and deterministic tests are harder, and thread count can grow unpredictably.

### Multiprocessing actor framework

Deferred because it adds raw-data transport and packaging complexity. It may be reconsidered for a narrowly sandboxed adapter.

### RabbitMQ or another broker

Rejected for v0.1. Persistent broker queues create an unacceptable alternate persistence path and are unnecessary for a single-user daemon.

## Verification

Issues #4, #7, and #8 must add tests proving:

- only lifecycle owns state transitions;
- mailbox capacity is bounded;
- stop/privacy commands remain deliverable under overload;
- cancellation propagates to every capture actor;
- late generation work is rejected by storage;
- actor crash and restart budgets fail closed;
- no queue fallback writes plaintext to disk;
- failure-injection tests remain non-zero.