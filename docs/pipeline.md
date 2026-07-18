# Bounded in-memory capture pipeline

Issue #8 implements the process-local data plane that carries capture work from raw frames to the encrypted persistence boundary. It follows ADR-0006: Pykka owns stage lifecycle and mutable worker state, while ZeroMQ carries bulk data through `inproc://` sockets.

## Stages

The pipeline has four distinct immutable work-item types:

```text
RawStageItem
  -> AnalyzedStageItem
  -> RedactedStageItem
  -> EncryptedStageItem
  -> EncryptedStageSink
```

Every item carries an opaque record UUID, the authoritative capture generation, the immutable configuration revision, a monotonic deadline, and one or more binary frames hidden from `repr`.

A processor must preserve the record ID, generation, and configuration revision and must return exactly the next stage type. Changed identifiers, stale generations, wrong output stages, malformed headers, and inconsistent frame lengths are rejected as protocol faults.

## Transport and bounds

All data-plane edges use fixed-role `inproc://` endpoints generated from opaque process-local IDs. Stage data never uses `ipc://`, `tcp://`, a filesystem path, or a broker.

Each stage is one bounded `pykka.ThreadingActor` that owns exactly one ZeroMQ `PULL` socket and at most one `PUSH` socket. Sockets are single-thread owned and configure finite timeouts, explicit high-water marks, immediate connected sends, and zero linger.

Pykka inboxes carry only small control messages. Bulk payloads remain in ZeroMQ multipart frames.

Every edge also has a fixed-capacity generation-scoped credit ledger. A sender must acquire a credit before sending, and the receiver releases it only after completion, cancellation, dropping, or fault cleanup. High-water marks are therefore not the sole memory bound.

Validated capture configuration controls `capture.raw_queue_items`, `capture.max_queue_items`, and `capture.overload_policy`. Queue values are restricted to 1 through 256.

## Framing

A multipart message contains a bounded UTF-8 JSON header validated by Pydantic and one or more bounded binary frames. The header contains protocol version, record UUID, generation, configuration revision, stage, monotonic deadline, frame count, and exact frame sizes.

Unknown fields, unsupported versions, excess frames or bytes, invalid identifiers, wrong stages, and length mismatches are rejected. The implementation does not use pickle, shelve, temporary files, or filesystem spooling.

## Overload behavior

`drop-newest` destroys the new raw buffer and returns a typed dropped result when the raw edge has no credit.

`coalesce-latest` keeps at most one additional raw item in process memory. A newer item replaces and zeroes the previous coalesced item. The coalesced item is flushed only through the capture gate when edge credit becomes available.

Internal edge saturation drops the current output and releases the upstream credit. It never creates another queue, retries indefinitely, writes a temporary file, switches transport, or reports a successful send.

## Buffer lifetime and lifecycle integration

Ingress accepts mutable `bytearray` frames. After a successful ZeroMQ copy, drop, replacement, or explicit clear, the original buffers are overwritten with zero bytes. The raw-stage actor reconstructs a private mutable buffer and overwrites it after processing or rejection.

Zeroing application buffers does not claim to erase copies that may briefly exist in Python, the operating system, or libzmq memory. Bounded credits, finite deadlines, zero linger, stage cleanup, and context destruction limit their lifetime.

Submission executes inside `CaptureGate.run_capture()`. Every stage checks cancellation, deadline, and the authoritative generation before processing and before forwarding. The encrypted sink executes inside `CaptureGate.run_persistence()`, preserving the final commit barrier from issue #7.

On stop or fault, the pipeline marks the generation cancelled, destroys coalesced work, waits for edge credits to reach zero, drains remaining socket frames inside their owning actors, and clears cancellation state. Stale work cannot reach the encrypted sink after generation invalidation.

## Faults and shutdown

Processor, protocol, transport, and persistence failures emit a sanitized event containing only record UUID, stage, and fixed fault code. Exception text and binary content are discarded. The lifecycle fault bridge converts this event into the authoritative actor-failure command.

Shutdown closes ingress, stops stage actors, closes sockets with zero linger, destroys the single ZeroMQ context, and leaves the Pykka registry clean.

Capture adapters must transfer ownership of mutable raw buffers to the pipeline and must not reuse them. Processors must not write stage payloads to disk. Storage may run only at the encrypted sink inside the lifecycle persistence callback.
