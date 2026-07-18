# Local Recall Product Requirements

**Status:** Draft for v0.1 implementation  
**Authority:** This document is the product-level source of truth for Local Recall v0.1. Architecture decisions may refine implementation details but may not weaken these requirements.  
**Tracking issue:** #1  
**Target release scope:** All P0 and P1 issues. P2 issues are deferred unless promoted explicitly.

## 1. Product definition

Local Recall is a local-first desktop activity recall system. While recording is explicitly enabled, it captures limited visual and desktop context, removes sensitive material before persistence, encrypts retained data, and lets the user later ask questions such as:

> What was I doing Saturday?

The system is not covert monitoring software. It is a single-user tool whose recording state must be obvious, controllable, and fail closed.

## 2. Normative language

The terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

- **Capture pipeline:** Automated work initiated by desktop recording, including metadata collection, screenshot capture, OCR, redaction, enrichment, embedding, summarization, and persistence.
- **Query pipeline:** Explicit user-requested retrieval and question answering over previously retained encrypted records.
- **Raw data:** Unredacted pixels, OCR output, metadata, prompts, or intermediate representations.
- **Retained data:** Redacted, encrypted records and their encrypted or threat-model-approved derived indexes.
- **Remote provider:** Any model or service whose execution occurs outside the local machine.
- **Fail closed:** Refuse capture, processing, egress, or persistence when a required control is unavailable or uncertain.

## 3. Product principles

1. **The off switch is authoritative.**
2. **Local processing is the default.**
3. **No raw capture data is written to disk.**
4. **Redaction occurs before persistence and before optional remote egress.**
5. **All retained capture content is encrypted.**
6. **Remote model use is explicit, constrained, and never an automatic privacy downgrade.**
7. **Answers remain traceable to retained source records.**
8. **Resource use remains bounded on ordinary local hardware.**
9. **Development follows test-driven development with honest failure propagation.**

## 4. v0.1 scope

### 4.1 Included

v0.1 MUST include:

- Linux desktop support on Xorg.
- Generic Xorg active-window metadata.
- A Qtile metadata adapter.
- Optional ActivityWatch metadata integration using its local API.
- Full-desktop screenshot capture with multi-monitor awareness.
- A hard capture gate with explicit lifecycle states.
- Application, title, workspace, lock-screen, idle, and manual privacy policies.
- Local OCR.
- Deterministic secret and sensitive-data detection.
- Pixel, text, and metadata redaction before persistence.
- Authenticated encryption and pluggable key providers.
- Encrypted storage, indexing, retention, deletion, backup, and restore.
- Local generation and embedding providers, with Ollama implemented first.
- Provider and routing strategies for optional remote AI services.
- Time-scoped retrieval, activity clustering, summaries, and cited answers.
- CLI controls, authenticated local IPC, and an always-visible recording indicator.
- Offline operation in local-only mode.
- Test-driven implementation and security/privacy invariant testing.

### 4.2 Explicit non-goals for v0.1

v0.1 MUST NOT include:

- Covert or hidden recording.
- Keylogging.
- Microphone, webcam, or ambient-audio recording.
- Clipboard capture.
- Browser-history import or account scraping.
- Process-memory inspection.
- Packet capture or pentesting telemetry ingestion.
- Multi-user monitoring.
- Employer, parental-control, or fleet-management features.
- Cloud synchronization.
- Automatic remote image upload.
- Windows or macOS support.
- Wayland capture.
- Biometric identification or inference of sensitive personal attributes.
- Autonomous action on the user’s behalf based on captured activity.

## 5. Users and primary use cases

### UC-001 — Explicitly control recording

The user can start, pause, resume, stop, and inspect capture state. Stop and privacy controls take priority over normal work.

### UC-002 — Recall a past period

The user can ask a natural-language, time-scoped question such as “What was I doing Saturday?” and receive a chronological answer grounded in retained records.

### UC-003 — Enter sensitive-work mode

The user can immediately suspend capture for sensitive work, including pentesting, authentication, password management, or a manually marked window/workspace.

### UC-004 — Exclude contexts

The user can define deterministic rules that deny screenshots, metadata, OCR, indexing, summarization, or remote egress for selected applications, titles, workspaces, domains, or times.

### UC-005 — Inspect and delete retained data

The user can inspect a timeline, preview redacted retained records on demand, and delete records by item, cluster, application, or time range.

### UC-006 — Operate fully locally

The user can capture, index, summarize, and query with networking disabled, subject to installed local model capability.

### UC-007 — Opt into a remote provider

The user can explicitly enable a supported remote provider and control which redacted data classes may leave the machine.

### UC-008 — Back up and restore

The user can export and restore encrypted records without producing plaintext archives or bundling active key material by default.

## 6. Capture states and semantics

The public state model MUST expose at least `off`, `recording`, `paused`, `locked`, `overloaded`, and `faulted`. Internal transitional states MAY include `starting`, `stopping`, and recovery states.

### STATE-001 — Off

While capture is `off`:

- No screenshots are taken.
- No automated desktop metadata is collected.
- No capture-triggered OCR, embedding, summarization, or model request begins.
- No capture-pipeline write occurs.
- Queued and in-flight capture work from the prior capture generation is invalidated and cannot persist.
- Volatile raw capture buffers are cleared as far as the runtime permits.
- Restarting the daemon does not silently resume recording.

An explicit query over previously retained encrypted data MAY run while capture is off. Query work is a separate read path and MUST NOT reactivate desktop capture.

### STATE-002 — Paused

While `paused`, no new capture begins. The daemon remains initialized for explicit resume. Entering pause MUST invalidate pending capture work unless a future architecture decision demonstrates an equally strong privacy guarantee.

### STATE-003 — Recording

While `recording`, capture occurs only when the capture gate, session state, and current policy all permit it. A continuously visible indicator MUST show recording state.

### STATE-004 — Locked

A locked desktop automatically denies capture. Locking invalidates pending capture work from the previous generation. Unlocking MUST NOT bypass normal resume policy.

### STATE-005 — Overloaded

When resource limits are exceeded, the system MUST drop, coalesce, reduce, pause, or fault capture according to explicit policy. It MUST NOT allow unbounded queues or stale backlog persistence.

### STATE-006 — Faulted

Missing encryption, failed redaction, insecure permissions, unsupported capture backend, invalid policy, or another critical privacy dependency MUST place capture in a non-recording faulted state.

## 7. Functional requirements

### 7.1 Capture control and scheduling

- **FR-CAP-001:** Capture MUST default to off on first start.
- **FR-CAP-002:** Start, pause, resume, stop, and privacy commands MUST be idempotent.
- **FR-CAP-003:** Stop and privacy commands MUST preempt lower-priority query, model, and capture work.
- **FR-CAP-004:** Every capture item MUST carry a session or generation token that prevents stale work from persisting after stop, pause, lock, fault, or restart.
- **FR-CAP-005:** Capture MUST support a configurable interval.
- **FR-CAP-006:** Meaningful active-window or workspace changes MAY trigger capture, subject to debounce and policy.
- **FR-CAP-007:** Near-identical frames MUST be deduplicated or coalesced before expensive downstream processing.
- **FR-CAP-008:** Queue depth, memory use, concurrency, and processing time MUST be bounded.
- **FR-CAP-009:** The Xorg backend MUST capture directly into memory without plaintext temporary files.
- **FR-CAP-010:** Multi-monitor geometry and timestamps MUST be retained as provenance.

### 7.2 Session and metadata discovery

- **FR-META-001:** The system MUST detect Xorg versus Wayland and MUST NOT guess when detection is uncertain.
- **FR-META-002:** Unsupported sessions MUST remain non-recording.
- **FR-META-003:** Metadata sources MUST implement a common strategy interface.
- **FR-META-004:** The system MUST support ordered composition of generic Xorg, Qtile, and ActivityWatch sources.
- **FR-META-005:** Every metadata field MUST include source provenance and, where relevant, confidence.
- **FR-META-006:** Generic Xorg metadata SHOULD include active application/class, optional title, geometry, desktop/workspace, and timestamp where available.
- **FR-META-007:** Qtile metadata SHOULD include focused window, group/workspace, layout, screen, application/class, and optional title.
- **FR-META-008:** ActivityWatch integration MUST query only the local API and only the time range needed for correlation.
- **FR-META-009:** URL capture through ActivityWatch MUST be disabled by default and MAY be reduced to domain-only.
- **FR-META-010:** Metadata collection MUST be independently disableable by field.

### 7.3 Capture policy

- **FR-POL-001:** Policy MUST be evaluated before screenshot capture whenever sufficient metadata is available.
- **FR-POL-002:** Policy MUST support application/class, title pattern, workspace/group, domain, full-screen state, metadata source, time window, lock state, idle state, and manual privacy mode.
- **FR-POL-003:** Policy MUST independently decide screenshot capture, metadata capture, OCR, indexing, summarization, and remote-provider eligibility.
- **FR-POL-004:** Password managers, lock screens, authentication dialogs, and explicitly configured sensitive pentesting contexts MUST be denied by default.
- **FR-POL-005:** Policy precedence and conflict resolution MUST be deterministic.
- **FR-POL-006:** Policy uncertainty after capture MUST reject the entire frame before persistence.
- **FR-POL-007:** Policy decisions MUST emit sanitized reason codes without captured content.
- **FR-POL-008:** Policy reload MUST be validated, atomic, and fail closed.

### 7.4 OCR and redaction

- **FR-RED-001:** OCR MUST execute locally by default.
- **FR-RED-002:** Raw OCR output MUST remain in memory only.
- **FR-RED-003:** Deterministic filters MUST detect common API keys, access tokens, private keys, authorization headers, passwords, connection strings, high-entropy values, email addresses, usernames, and user-configured patterns.
- **FR-RED-004:** Secret findings tied to OCR coordinates MUST redact the matching screenshot pixels.
- **FR-RED-005:** Matching OCR text and metadata fields MUST be removed or replaced before persistence.
- **FR-RED-006:** A model MAY assist classification only after deterministic controls and MUST NOT be the sole secret detector.
- **FR-RED-007:** Low-confidence sensitive findings MUST follow a conservative configurable policy.
- **FR-RED-008:** Allowlisting MUST be explicit, narrow, and auditable.
- **FR-RED-009:** Any redaction-stage failure MUST reject the complete record.
- **FR-RED-010:** Unredacted frame types MUST be structurally incompatible with storage and remote-provider interfaces.

### 7.5 Encryption, key management, and storage

- **FR-STO-001:** All retained screenshots, OCR text, metadata, prompts, summaries, embeddings, and derived content MUST be encrypted or protected by a design explicitly accepted by the threat model.
- **FR-STO-002:** Encryption MUST use authenticated, versioned envelopes.
- **FR-STO-003:** Storage interfaces MUST accept encrypted envelopes only.
- **FR-STO-004:** Key providers MUST be replaceable behind a strategy interface.
- **FR-STO-005:** GPG MAY be configured as a fallback key/encryption provider but MUST NOT be selected silently.
- **FR-STO-006:** Missing, locked, revoked, or invalid key material MUST prevent persistence and place capture in a non-recording state.
- **FR-STO-007:** Key material MUST NOT appear in application configuration, logs, diagnostics, exports, or captured records.
- **FR-STO-008:** Writes MUST be atomic and recoverable after interruption.
- **FR-STO-009:** Record schemas and encryption envelopes MUST be versioned and migratable.
- **FR-STO-010:** Filesystem inspection MUST reveal no plaintext screenshot, OCR text, title, prompt, summary, or thumbnail.
- **FR-STO-011:** Storage permissions MUST be owner-only by default and insecure permissions MUST block capture.
- **FR-STO-012:** Corrupt or unauthenticated records MUST be quarantined without exposing content.

### 7.6 Model providers and routing

- **FR-AI-001:** Generation, embedding, and optional vision capability MUST be represented by provider strategy interfaces.
- **FR-AI-002:** Ollama MUST be the first implemented local provider.
- **FR-AI-003:** The system MUST be designed to work with approximately 7B–9B instruct models for ordinary summarization and question answering.
- **FR-AI-004:** Provider capabilities, context limits, structured-output support, availability, and privacy classification MUST be discoverable.
- **FR-AI-005:** Routing policies MUST include `privacy-strict`, `local-only`, `local-first`, and `remote-explicit`.
- **FR-AI-006:** Remote providers MUST be disabled by default.
- **FR-AI-007:** Local provider failure MUST NOT silently trigger remote fallback.
- **FR-AI-008:** Remote egress MUST be separately authorized by data class; images MUST be denied remotely by default.
- **FR-AI-009:** Remote payloads MUST be redacted, size-limited, inspected, and audited before egress.
- **FR-AI-010:** Provider credentials MUST be resolved through a key provider.
- **FR-AI-011:** Provider requests MUST support cancellation, timeout, and bounded concurrency.
- **FR-AI-012:** Capture and indexing MAY continue without a generation model when policy allows.
- **FR-AI-013:** No model may receive raw, unredacted capture data.
- **FR-AI-014:** The system MUST NOT download a model implicitly while recording.

### 7.7 Retrieval, clustering, and answers

- **FR-RET-001:** Queries MUST resolve explicit and relative time expressions in the configured local timezone.
- **FR-RET-002:** Retrieval MUST combine time, application, workspace, keyword, metadata, and semantic filters.
- **FR-RET-003:** Query execution MUST decrypt only the minimum selected working set.
- **FR-RET-004:** Decrypted query working data MUST be discarded after completion or cancellation.
- **FR-RET-005:** Captures MUST be clusterable into activity spans using time, context changes, perceptual similarity, and semantic similarity.
- **FR-RET-006:** Every cluster and summary MUST retain exact source-record membership.
- **FR-RET-007:** Every factual answer claim MUST cite one or more retained records or activity clusters with timestamps.
- **FR-RET-008:** Answers MUST distinguish observation, model inference, and unavailable information.
- **FR-RET-009:** Weak or empty retrieval MUST produce an insufficient-evidence result rather than fabricated continuity.
- **FR-RET-010:** Local-only query execution MUST make no network request.

### 7.8 User controls and local API

- **FR-CTL-001:** The CLI MUST provide start, pause, resume, stop, privacy, status, ask, timeline, search, health, provider, configuration, and storage commands.
- **FR-CTL-002:** Control and query clients MUST communicate through authenticated local IPC.
- **FR-CTL-003:** Linux IPC SHOULD use an owner-only Unix-domain socket and MUST bind no TCP listener by default.
- **FR-CTL-004:** Another local user MUST NOT be able to control or query the daemon.
- **FR-CTL-005:** Status MUST distinguish off, recording, paused, privacy mode, locked, overloaded, and faulted.
- **FR-CTL-006:** A continuously visible status indicator MUST reflect daemon-confirmed state.
- **FR-CTL-007:** The indicator MUST provide one-action stop and privacy controls.
- **FR-CTL-008:** Notifications and status surfaces MUST NOT display screenshot thumbnails, OCR text, titles, prompts, or secrets.
- **FR-CTL-009:** Timeline inspection MUST expose provenance and redaction status without relying solely on AI summaries.
- **FR-CTL-010:** Deletion MUST support individual records, clusters, applications, time ranges, and purge-all.
- **FR-CTL-011:** Deletion MUST update blobs, indexes, summaries, and citations atomically or recoverably.

### 7.9 Retention, backup, and recovery

- **FR-LIFE-001:** Retention MUST be configurable by age, total size, application, workspace, and record type.
- **FR-LIFE-002:** Storage MUST enforce high/low watermarks and a deterministic eviction policy.
- **FR-LIFE-003:** Garbage collection MUST be restartable and remove expired data from derived structures.
- **FR-LIFE-004:** Cryptographic deletion SHOULD be used where practical.
- **FR-LIFE-005:** Backup exports MUST remain encrypted and MUST NOT include active key material by default.
- **FR-LIFE-006:** Portable exports MAY support explicit GPG recipient encryption.
- **FR-LIFE-007:** Restore MUST validate integrity, schema compatibility, duplicates, and key availability.
- **FR-LIFE-008:** Backup, restore, deletion, and key operations MUST emit sanitized audit events.

## 8. Privacy and security invariants

- **INV-001 — Hard off:** No autonomous capture-pipeline operation or persistence can occur while off.
- **INV-002 — No plaintext persistence:** Raw or redacted capture content is never written to disk unencrypted.
- **INV-003 — Redact before retain:** Redaction completes successfully before encryption and persistence.
- **INV-004 — Fail closed:** Missing or uncertain critical privacy controls deny capture or persistence.
- **INV-005 — Stale work cannot persist:** Work from an invalid capture generation cannot write data.
- **INV-006 — Local by default:** Default operation requires no remote provider.
- **INV-007 — No implicit egress downgrade:** A local failure cannot select a remote provider automatically.
- **INV-008 — Sanitized observability:** Logs, errors, metrics, diagnostics, and CI artifacts contain no captured content or secrets.
- **INV-009 — Visible recording:** Recording cannot occur without a continuously visible daemon-confirmed indicator.
- **INV-010 — Least-privilege IPC:** Only the owning user can control or query the daemon.
- **INV-011 — Bounded work:** Queues, memory, concurrency, retries, and timeouts are bounded.
- **INV-012 — Traceable answers:** Factual answer claims map to retained source records.
- **INV-013 — Explicit destructive scope:** Deletion and export operations require an explicit scope and are auditable.
- **INV-014 — No model-only secret control:** Deterministic redaction controls remain authoritative.
- **INV-015 — No hidden capture expansion:** New capture data classes require an explicit requirements change and policy surface.

## 9. Non-functional requirements

- **NFR-001 — Offline capability:** Local-only capture, indexing, summarization, and query MUST work with networking disabled when required local models are installed.
- **NFR-002 — Hardware target:** The core system MUST remain usable with CPU inference or a modest local GPU and approximately 8B-class models.
- **NFR-003 — Bounded resources:** Long-running operation MUST demonstrate bounded memory, queue depth, worker count, and storage growth.
- **NFR-004 — Responsiveness:** Stop and privacy commands MUST be processed ahead of ordinary work and complete within a measurable release target.
- **NFR-005 — Determinism:** State transitions, policy precedence, schema validation, and failure behavior MUST be deterministic.
- **NFR-006 — Replaceability:** Capture, metadata, OCR, encryption, key, storage, embedding, generation, and routing implementations MUST be replaceable through narrow contracts.
- **NFR-007 — Testability:** Time, providers, capture sources, metadata sources, storage, and IPC MUST support deterministic synthetic tests.
- **NFR-008 — Reproducibility:** The development and release environments MUST be reproducible, including Nix support.
- **NFR-009 — Upgrade safety:** Schema and key migrations MUST be restartable, integrity checked, and unable to create plaintext intermediates.
- **NFR-010 — Accessibility:** Critical stop/privacy controls MUST be keyboard accessible.
- **NFR-011 — No telemetry:** The application MUST include no third-party analytics or telemetry.
- **NFR-012 — Time correctness:** Stored timestamps and relative-date queries MUST preserve timezone and daylight-saving semantics.

## 10. Test-driven development and test integrity

- **TDD-001:** Feature work MUST begin with a focused failing test that expresses the next required behavior.
- **TDD-002:** The developer MUST verify that the test fails for the expected reason before implementation.
- **TDD-003:** Implementation MUST add only enough behavior to pass, followed by refactoring while the suite remains green.
- **TDD-004:** Every defect fix MUST begin with a regression test that reproduces the defect.
- **TDD-005:** Every implementation issue MUST add or update tests covering its acceptance criteria.
- **TDD-006:** Unit, integration, security/privacy invariant, and end-to-end tests MUST be used where component boundaries differ.
- **TDD-007:** Assertion failures, collection/import errors, fixture failures, setup/teardown failures, crashes, signals, timeouts, subprocess failures, sanitizer findings, and performance-gate failures MUST return non-zero.
- **TDD-008:** Zero discovered, selected, or executed required tests MUST return non-zero.
- **TDD-009:** Test wrappers and CI pipelines MUST preserve the original failing exit status, including piped output.
- **TDD-010:** Required test paths MUST NOT use `|| true`, `|| :`, unconditional `exit 0`, swallowed exceptions, `continue-on-error`, `allow_failure`, or pass-with-no-tests behavior.
- **TDD-011:** Required tests MUST NOT be skipped, disabled, marked expected-failure, weakened, or filtered out merely to obtain a passing build.
- **TDD-012:** Test and CI paths MUST include failure-injection meta-tests proving that known failures reach the top-level non-zero status.
- **TDD-013:** Tests MUST use synthetic capture fixtures and MUST NOT inspect the developer’s real screen or retained personal data.
- **TDD-014:** Release reports MUST include discovered, executed, passed, failed, skipped, and expected-failure counts for every required suite.
- **TDD-015:** At release time, required skipped and expected-failure counts MUST be zero.

Pure specification work, including this document, is verified through requirements review and traceability. Executable TDD begins when the test harness is established in issue #4; no production implementation may precede that harness.

## 11. Required data lifecycle

The capture data path MUST follow this order:

1. Confirm lifecycle state and capture generation.
2. Collect only policy-approved minimal metadata.
3. Evaluate pre-capture policy.
4. Capture pixels directly into memory.
5. Perform local OCR and deterministic detection in memory.
6. Redact screenshot pixels, OCR text, and metadata.
7. Reject the complete record if policy or redaction is uncertain or fails.
8. Encrypt the approved redacted record.
9. Persist only the encrypted envelope.
10. Create only encrypted or threat-model-approved derived indexes and summaries.
11. Retrieve and decrypt the minimum working set for an explicit query.
12. Discard decrypted query working data after completion or cancellation.
13. Apply retention or explicit deletion across records and all derived structures.

No provider, plugin, script, debug path, migration, export, or repair operation may bypass this ordering.

## 12. Acceptance scenarios

### AC-001 — Hard off

**Given** the daemon is off  
**When** time passes, focus changes, metadata sources emit events, or stale jobs complete  
**Then** no screenshot, metadata record, OCR operation, capture-triggered model request, or capture persistence occurs.

### AC-002 — Stop invalidates stale work

**Given** capture work is queued or in flight  
**When** the user stops capture  
**Then** all prior-generation work is unable to persist, and status confirms off.

### AC-003 — Sensitive pre-capture denial

**Given** the focused context matches a denied password-manager or sensitive-work rule  
**When** a capture trigger occurs  
**Then** no screenshot is taken and the audit log records only a sanitized denial reason.

### AC-004 — Secret redaction

**Given** a synthetic screenshot contains seeded API keys, credentials, and high-entropy values  
**When** the frame is processed  
**Then** corresponding pixels and text are redacted before encryption, and seeded values appear nowhere in storage, logs, diagnostics, exports, or provider requests.

### AC-005 — Encryption failure

**Given** the configured key is unavailable or invalid  
**When** capture attempts to persist a record  
**Then** no record is stored and capture transitions to a non-recording faulted state.

### AC-006 — Local-only operation

**Given** local-only mode and networking disabled  
**When** the user records a synthetic activity session and asks a question  
**Then** capture, indexing, summarization, retrieval, and cited answering complete without a remote request.

### AC-007 — Optional remote provider

**Given** a remote provider is configured but remote use is not explicitly enabled for the current data class  
**When** the local provider fails  
**Then** no remote request occurs.

### AC-008 — Saturday recall

**Given** retained synthetic activity across several days  
**When** the user asks “What was I doing Saturday?”  
**Then** the system resolves the correct absolute Saturday in the configured timezone and returns a chronological answer whose factual claims cite source timestamps.

### AC-009 — Lock screen

**Given** capture is recording  
**When** the desktop locks  
**Then** new capture stops and queued prior-generation work cannot persist until normal resume policy permits recording.

### AC-010 — Deletion

**Given** a retained activity cluster  
**When** the user deletes that cluster  
**Then** its blobs, indexes, summaries, and citations are removed atomically or through a recoverable transaction and it no longer appears in answers.

### AC-011 — Honest test failure

**Given** a deliberately failing assertion, collection error, crash, timeout, teardown failure, or empty required test selection  
**When** the canonical test command and CI job run  
**Then** each exits non-zero and the failure cannot be relabeled as success.

## 13. MVP completion checklist

v0.1 is complete only when:

- [ ] Product requirements, threat model, and architecture agree.
- [ ] Capture defaults to off and the hard-off invariant is proven.
- [ ] Xorg, Qtile, and optional ActivityWatch metadata paths are implemented.
- [ ] Sensitive contexts are denied before screenshot capture where possible.
- [ ] OCR and deterministic secret redaction operate locally.
- [ ] No plaintext capture data appears on disk, in logs, diagnostics, exports, CI, or model requests.
- [ ] Encryption and key failures fail closed.
- [ ] Encrypted storage, indexing, retention, deletion, backup, and restore are implemented.
- [ ] Local generation and embedding work with an approximately 8B-class setup.
- [ ] Remote providers remain optional, explicit, and unable to receive raw data.
- [ ] “What was I doing Saturday?” produces a correct cited synthetic result.
- [ ] CLI, authenticated IPC, and a continuously visible recording indicator are implemented.
- [ ] Required unit, integration, security/privacy, and end-to-end suites execute and pass.
- [ ] Failure-injection tests prove no false-green test or CI path.
- [ ] Required skipped and expected-failure counts are zero.
- [ ] Reproducible NixOS packaging and release documentation are complete.

## 14. Deferred work

The following remain deferred to P2 unless explicitly promoted:

- Local vision-model enrichment.
- General allowlisted script-based metadata adapters.
- Wayland portal capture.
- Rich local timeline/privacy web UI.
- Additional platform packaging beyond the initial NixOS target.

## 15. Change control

A change that weakens an invariant, adds a capture data class, enables a new remote egress path, alters off-state semantics, or permits plaintext persistence requires:

1. An explicit requirements change.
2. Threat-model review.
3. New failing security/privacy tests before implementation.
4. Updated user-visible policy and status controls.
