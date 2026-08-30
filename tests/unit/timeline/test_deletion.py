from __future__ import annotations

import asyncio
from pathlib import Path
from uuid import UUID

import pytest

from local_recall.ports.storage import DeleteRequest, DeleteResult
from local_recall.timeline.deletion import DeletionCoordinator, DeletionJournal, DeletionPhase

FIRST = UUID("00000000-0000-4000-8000-000000000001")
SECOND = UUID("00000000-0000-4000-8000-000000000002")


class FakeStorage:
    def __init__(self) -> None:
        self.deleted: list[UUID] = []

    async def delete(self, request: DeleteRequest) -> DeleteResult:
        self.deleted.append(request.record_id)
        return DeleteResult(request.record_id, True, False)


class FakeSemanticIndex:
    def __init__(self, *, fail_once: bool = False) -> None:
        self.removed: list[tuple[UUID, ...]] = []
        self.fail_once = fail_once

    async def remove(self, record_ids: tuple[UUID, ...]) -> object:
        self.removed.append(record_ids)
        if self.fail_once:
            self.fail_once = False
            raise RuntimeError("synthetic derived-state failure")
        return object()


class FakeActivityReconciler:
    def __init__(self) -> None:
        self.deleted: list[tuple[UUID, ...]] = []

    async def reconcile_deleted(self, record_ids: tuple[UUID, ...]) -> None:
        self.deleted.append(record_ids)


def test_deletion_journal_is_owner_only_content_free_and_round_trips(tmp_path: Path) -> None:
    root = tmp_path / "deletion"
    journal = DeletionJournal(root)

    asyncio.run(journal.begin("request-1", (FIRST, SECOND)))
    state = asyncio.run(journal.load())

    assert state is not None
    assert state.request_id == "request-1"
    assert state.record_ids == (FIRST, SECOND)
    assert state.phase is DeletionPhase.PLANNED
    payload = (root / "deletion-intent.json").read_bytes()
    assert b"request-1" in payload
    assert b"window-title" not in payload
    assert oct(root.stat().st_mode & 0o777) == "0o700"
    assert oct((root / "deletion-intent.json").stat().st_mode & 0o777) == "0o600"


def test_deletion_journal_recovers_from_stale_temporary_file(tmp_path: Path) -> None:
    root = tmp_path / "deletion"
    journal = DeletionJournal(root)
    temporary = root / ".deletion-intent.json.tmp"
    temporary.write_bytes(b"interrupted-private-state")
    temporary.chmod(0o600)

    state = asyncio.run(journal.begin("request-1", (FIRST, SECOND)))

    assert state.phase is DeletionPhase.PLANNED
    assert asyncio.run(journal.load()) == state
    assert not temporary.exists()


def test_deletion_resumes_forward_after_derived_state_failure(tmp_path: Path) -> None:
    async def exercise() -> None:
        journal = DeletionJournal(tmp_path / "deletion")
        storage = FakeStorage()
        index = FakeSemanticIndex(fail_once=True)
        activity = FakeActivityReconciler()
        coordinator = DeletionCoordinator(
            journal=journal,
            storage=storage,
            semantic_index=index,
            activity_reconciler=activity,
        )

        with pytest.raises(RuntimeError, match="derived-state"):
            await coordinator.delete(
                request_id="request-1",
                record_ids=(FIRST, SECOND),
            )

        interrupted = await journal.load()
        assert interrupted is not None
        assert interrupted.phase is DeletionPhase.RECORDS_DELETED
        assert storage.deleted == [FIRST, SECOND]
        assert activity.deleted == []

        await coordinator.recover()

        assert storage.deleted == [FIRST, SECOND]
        assert index.removed == [(FIRST, SECOND), (FIRST, SECOND)]
        assert activity.deleted == [(FIRST, SECOND)]
        assert await journal.load() is None

    asyncio.run(exercise())


def test_deletion_scope_is_explicit_unique_and_idempotent(tmp_path: Path) -> None:
    async def exercise() -> None:
        journal = DeletionJournal(tmp_path / "deletion")
        storage = FakeStorage()
        index = FakeSemanticIndex()
        activity = FakeActivityReconciler()
        coordinator = DeletionCoordinator(
            journal=journal,
            storage=storage,
            semantic_index=index,
            activity_reconciler=activity,
        )

        with pytest.raises(ValueError, match="at least one"):
            await coordinator.delete(request_id="request-empty", record_ids=())
        with pytest.raises(ValueError, match="duplicate"):
            await coordinator.delete(request_id="request-duplicate", record_ids=(FIRST, FIRST))

        result = await coordinator.delete(request_id="request-1", record_ids=(FIRST, SECOND))
        assert result.deleted_count == 2
        assert result.recovered is False
        assert await journal.load() is None

        repeated = await coordinator.delete(request_id="request-2", record_ids=(FIRST, SECOND))
        assert repeated.deleted_count == 2
        assert repeated.recovered is False
        assert await journal.load() is None

    asyncio.run(exercise())
