from __future__ import annotations

import asyncio
import os
import stat
from pathlib import Path
from uuid import UUID

import pytest

from local_recall.timeline.deletion import DeletionJournal, DeletionPhase

FIRST = UUID("00000000-0000-4000-8000-000000000001")
SECOND = UUID("00000000-0000-4000-8000-000000000002")


def test_journal_root_symlink_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.mkdir()
    link = tmp_path / "deletion"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="real directory"):
        DeletionJournal(link)


def test_journal_root_group_writable_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "deletion"
    root.mkdir()
    root.chmod(0o770)

    with pytest.raises(ValueError, match="owner-only"):
        DeletionJournal(root)


def test_journal_root_foreign_owner_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "deletion"
    root.mkdir()
    root.chmod(0o700)
    real_uid = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: real_uid + 1)

    with pytest.raises(ValueError, match="owner"):
        DeletionJournal(root)


def test_journal_symlinked_file_is_rejected_on_load(tmp_path: Path) -> None:
    root = tmp_path / "deletion"
    journal = DeletionJournal(root)
    asyncio.run(journal.begin("request-1", (FIRST,)))
    real = root / "deletion-intent.json"
    decoy = tmp_path / "decoy.json"
    decoy.write_bytes(real.read_bytes())
    real.unlink()
    real.symlink_to(decoy)

    with pytest.raises(RuntimeError, match="unsafe"):
        asyncio.run(journal.load())


def test_journal_non_regular_file_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "deletion"
    journal = DeletionJournal(root)
    asyncio.run(journal.begin("request-1", (FIRST,)))
    path = root / "deletion-intent.json"
    path.unlink()
    path.mkdir()

    with pytest.raises(RuntimeError, match="unsafe"):
        asyncio.run(journal.load())


def test_journal_group_readable_file_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "deletion"
    journal = DeletionJournal(root)
    asyncio.run(journal.begin("request-1", (FIRST,)))
    (root / "deletion-intent.json").chmod(0o644)

    with pytest.raises(RuntimeError, match="owner-only"):
        asyncio.run(journal.load())


def test_journal_foreign_owned_file_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "deletion"
    journal = DeletionJournal(root)
    asyncio.run(journal.begin("request-1", (FIRST,)))
    real_uid = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: real_uid + 1)

    with pytest.raises(RuntimeError, match="owner-only"):
        asyncio.run(journal.load())


def test_journal_oversized_file_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "deletion"
    journal = DeletionJournal(root)
    path = root / "deletion-intent.json"
    path.write_bytes(b"x" * (64 * 1024 + 1))
    path.chmod(0o600)

    with pytest.raises(RuntimeError, match="size"):
        asyncio.run(journal.load())


def test_journal_tampered_payload_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "deletion"
    journal = DeletionJournal(root)
    path = root / "deletion-intent.json"
    path.write_bytes(b'{"phase":"planned","record_ids":[],"request_id":"r","version":2}')
    path.chmod(0o600)

    with pytest.raises(RuntimeError, match="invalid"):
        asyncio.run(journal.load())


def test_journal_temporary_symlink_is_replaced_without_following(
    tmp_path: Path,
) -> None:
    root = tmp_path / "deletion"
    journal = DeletionJournal(root)
    temporary = root / ".deletion-intent.json.tmp"
    decoy = tmp_path / "decoy-target"
    decoy.write_bytes(b"do-not-touch")
    temporary.symlink_to(decoy)

    state = asyncio.run(journal.begin("request-1", (FIRST, SECOND)))

    assert state.phase is DeletionPhase.PLANNED
    assert not temporary.is_symlink()
    assert decoy.read_bytes() == b"do-not-touch"
    assert (root / "deletion-intent.json").exists()


def test_journal_clear_refuses_symlinked_file(tmp_path: Path) -> None:
    root = tmp_path / "deletion"
    journal = DeletionJournal(root)
    path = root / "deletion-intent.json"
    decoy = tmp_path / "decoy.json"
    decoy.write_bytes(b"keep-me")
    path.symlink_to(decoy)

    with pytest.raises(RuntimeError, match="unsafe"):
        asyncio.run(journal.clear())

    assert decoy.read_bytes() == b"keep-me"


def test_journal_clear_removes_regular_file_and_fsyncs(tmp_path: Path) -> None:
    root = tmp_path / "deletion"
    journal = DeletionJournal(root)
    asyncio.run(journal.begin("request-1", (FIRST,)))
    path = root / "deletion-intent.json"
    assert path.exists()

    asyncio.run(journal.clear())

    assert not path.exists()
    info = root.stat()
    assert stat.S_IMODE(info.st_mode) & 0o077 == 0
