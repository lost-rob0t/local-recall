# Architecture Decision Records

Architecture decisions are immutable historical records. When a decision changes, add a new ADR that supersedes the old one rather than rewriting history without explanation.

| ADR | Status | Decision |
|---|---|---|
| [0001](0001-python-runtime.md) | Accepted, amended by 0006 | Use Python 3.13+ for the v0.1 daemon. |
| [0002](0002-supervised-actors.md) | Superseded by 0006 | Earlier AnyIO actor-style concurrency design. |
| [0003](0003-encrypted-storage.md) | Accepted | Use a minimal SQLite catalog with encrypted opaque blobs. |
| [0004](0004-envelope-encryption.md) | Accepted | Use per-artifact envelope encryption with XChaCha20-Poly1305. |
| [0005](0005-extension-boundaries.md) | Accepted | Use static capability-limited extension boundaries. |
| [0006](0006-pykka-zmq-actors.md) | Accepted | Use Pykka actors with ZeroMQ transport and no external broker. |

## Required ADR changes

Add or supersede an ADR when changing runtime, actor framework, transport, process boundaries, lifecycle authority, storage leakage, encryption/key hierarchy, plugin loading, remote egress, or the persistent artifact set.

A decision that weakens a privacy invariant also requires requirements and threat-model updates plus a failing security test before implementation.
