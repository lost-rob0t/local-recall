# ADR-0007: Target CPython 3.14 for v0.1

- **Status:** Accepted
- **Date:** 2026-07-17
- **Decision owners:** Local Recall project
- **Amends:** ADR-0001 runtime-version decision
- **Related:** #4, `NFR-002`, `NFR-006`, `NFR-007`, `NFR-008`

## Context

ADR-0001 selected Python 3.13 or newer before the executable project scaffold existed. The project owner has selected Python 3.14 as the concrete v0.1 runtime target.

Using one Python feature series across packaging, bootstrap, CI, static analysis, and Nix avoids accidental support claims for an interpreter that is not continuously tested. It also prevents developers from producing a passing local result under Python 3.13 while release CI uses Python 3.14.

## Decision

Local Recall v0.1 targets the standard CPython 3.14 series.

- `pyproject.toml` requires `>=3.14,<3.15`.
- The canonical bootstrap creates a Python 3.14 environment.
- GitHub Actions runs every required job on Python 3.14.
- Ruff and Pyright target Python 3.14 syntax and typing behavior.
- The Nix development shell provides `python314`.
- A required unit test rejects execution under another Python feature series.
- Dependency locks must be installable and tested under Python 3.14.

The normal GIL-enabled CPython build is the supported v0.1 runtime. Python 3.14 free-threaded builds are not an implicit support target. Supporting them requires explicit actor, native-extension, OCR, image-processing, PyZMQ, and shutdown testing plus a later ADR.

## Consequences

### Positive

- Development and CI execute against the same Python feature series.
- Packaging metadata communicates the actual supported runtime.
- New Python 3.14 language and typing behavior can be used without maintaining a 3.13 compatibility path.
- Pykka, PyZMQ, Pydantic, and native dependencies are validated against the release runtime rather than assumed compatible.

### Negative

- Python 3.13 installations cannot install Local Recall v0.1.
- Contributors need Python 3.14 or the provided Nix environment.
- A dependency without Python 3.14 support blocks the build instead of silently lowering the runtime target.
- Free-threaded Python remains untested and unsupported for v0.1.

## Verification

Issue #4 and later release checks must prove:

- the project metadata rejects Python 3.13;
- bootstrap selects Python 3.14;
- both supported Ubuntu CI environments pass under Python 3.14;
- the Nix shell exposes Python 3.14;
- Ruff and Pyright are configured for Python 3.14;
- required tests fail when executed under the wrong Python feature series;
- the exact dependency lock installs successfully under Python 3.14.
