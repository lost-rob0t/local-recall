# Capture lifecycle and hard gate

Issue #7 establishes the process-wide authority for capture state. The implementation uses a Pykka `LifecycleActor` as the sole state-transition owner and a thread-safe `CaptureGate` as the mandatory boundary around capture and persistence operations.

## States

The v0.1 capture lifecycle uses these operational states:

- `off` — no capture, capture-triggered processing, or persistence is authorized;
- `starting` — configuration is accepted and preflight is running, but capture and persistence remain closed;
- `recording` — new capture and current-generation persistence are authorized;
- `paused` — new capture is blocked while already-redacted current-generation work may finish persistence;
- `stopping` — the prior generation is invalidated and cancellation/quiescence cleanup is running;
- `faulted` — capture and persistence are closed because a critical invariant or dependency failed.

The domain model retains the reserved `privacy` state for the later manual-privacy-mode issue. Issue #7 does not enter it.

## Ownership

`LifecycleActor` is a `pykka.ThreadingActor` and is the only component allowed to mutate lifecycle state. Pykka serializes lifecycle commands in one actor inbox. Direct mutation from another thread raises `CaptureGateOwnershipError`.

A second private Pykka actor runs potentially blocking preflight checks. This prevents preflight from blocking the lifecycle control inbox. A stop command received during `starting` therefore invalidates the generation before preflight returns.

Pykka inboxes carry lifecycle control messages only. Bulk capture data remains reserved for the bounded ZeroMQ pipeline implemented by issue #8.

## Startup

Every new `CaptureGate` starts in `off` with no generation. Runtime state is not persisted.

The actor starts capture only when the current validated configuration has `capture.enabled = true`. That setting is the explicit startup opt-in. The safe default from issue #6 leaves it false, so a daemon restart does not infer authorization from the previous process state.

Startup preflight must verify session support, encryption availability, policy readiness, and other critical dependencies before the state can become `recording`. A failed or late preflight transitions to `faulted`; it never enters `recording`.

## Generation invalidation

Each start allocates a new positive `CaptureGeneration`. Every preflight, capture, and persistence operation registers against that generation and receives a read-only `CaptureWorkPermit` containing:

- the generation;
- the immutable configuration revision;
- a cooperative cancellation signal.

Stop and fault perform generation invalidation while holding the persistence commit barrier:

1. signal the active generation's cancellation event;
2. move the generation into draining state;
3. increment the generation epoch;
4. clear the active generation;
5. transition to `stopping` or `faulted`;
6. release the barrier and begin bounded cleanup.

After step 4, new capture fails with `CaptureGateClosed`, and old persistence fails with `CaptureGateClosed` or `StaleCaptureGeneration`.

## Persistence barrier

`CaptureGate.run_persistence()` holds a dedicated commit lock across the final generation check and the supplied commit operation. Stop and fault acquire the same lock before invalidation.

This defines a deterministic ordering:

- a commit that acquired the barrier first belongs to the pre-stop history and finishes before invalidation;
- stop/fault that acquired the barrier first invalidates the generation, and the stale commit callback is never invoked.

Concrete storage code must place its final irreversible commit inside `run_persistence()`.

## Stop barrier

After invalidation, `LifecycleActor` performs all cleanup paths with one shared finite deadline:

1. request cancellation of queued work;
2. request cancellation of in-flight work;
3. wait for gate-registered operations to leave;
4. wait for the pipeline coordinator to report quiescence;
5. clear volatile buffers.

Queued and in-flight cancellation are attempted independently. Failure of one does not skip the other. Volatile-buffer clearing is attempted even after cancellation or quiescence failure.

The state becomes `off` only after the barrier succeeds. A cancellation error, timeout, or buffer-clear error leaves the gate closed and transitions to `faulted`.

## Preflight cancellation

The private preflight actor registers its check as `starting`-generation work. The preflight request receives the same cooperative cancellation signal as later work.

When stop arrives during preflight:

- the lifecycle actor remains responsive;
- the gate immediately transitions to `stopping` and rejects capture/persistence;
- the preflight cancellation signal is set;
- stop waits only for the configured finite barrier;
- a late success result is ignored because its generation is stale.

An uncooperative preflight can delay quiescence only until the stop deadline. The lifecycle then becomes `faulted`; it never reopens the gate.

## Fault behavior

The following fault codes are sanitized identifiers rather than exception text or captured content:

- `unsupported_session`;
- `encryption_unavailable`;
- `policy_failure`;
- `preflight_failure`;
- `preflight_timeout`;
- `cancellation_failure`;
- `quiescence_timeout`;
- `buffer_clear_failure`;
- `audit_failure`;
- `actor_failure`;
- `shutdown_failure`.

Unsupported control messages fault closed without storing or emitting the message body.

## Audit events

Every actual transition emits `LifecycleAuditEvent` with only:

- event ID and fixed event type;
- previous and current state;
- transition reason;
- numeric generation epoch;
- configuration revision identifier, when active;
- timezone-aware occurrence time;
- optional sanitized fault code.

Events do not contain captured pixels, OCR, metadata values, prompts, exception objects, arbitrary messages, or payloads. Audit-sink failure itself faults capture closed.

## Command semantics

Commands are serialized by `LifecycleActor` and return `LifecycleCommandResult`.

- repeated start while `starting` or `recording` is accepted without another transition;
- repeated pause, resume, stop, and fault commands are deterministic and idempotent for their current state;
- start returns after entering `starting`; recording is observable only after the asynchronous preflight completion message is accepted;
- stop returns after the stop barrier reaches `off` or `faulted`.

## Required integration rule

Capture, OCR-triggering dispatch, redaction pipeline ingress, and persistence code must not inspect lifecycle state and then act separately. They must execute through the corresponding gate method so the authorization check and operation registration are atomic.

## Automatic session-safety pause

Lock and configured idle pauses reuse the lifecycle capture generation. Entering an automatic safety pause cancels the prior generation and allocates a fresh paused generation; unlock/activity can resume only that fresh generation. Manual pause remains independent. See [session-safety.md](session-safety.md).
