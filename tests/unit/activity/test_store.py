from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from local_recall.activity import store as activity_store
from local_recall.activity.clustering import ActivityCluster
from local_recall.activity.summaries import ActivitySummary
from local_recall.crypto import OSKeyringProvider


class MemoryKeyringBackend:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.values.pop((service, username), None)


NOW = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
FIRST = UUID("00000000-0000-4000-8000-000000000001")
SECOND = UUID("00000000-0000-4000-8000-000000000002")


def make_store(path: Path) -> activity_store.EncryptedActivityStore:
    return activity_store.EncryptedActivityStore(
        path,
        OSKeyringProvider(MemoryKeyringBackend()),
    )


def entry(*, second: bool = False) -> activity_store.ActivityEntry:
    source_ids = (FIRST, SECOND) if second else (FIRST,)
    cluster = ActivityCluster(
        source_record_ids=source_ids,
        started_at=NOW,
        ended_at=NOW + (timedelta(minutes=5) if second else timedelta()),
    )
    summary = ActivitySummary(
        text="reviewed the redacted project notes",
        source_record_ids=source_ids,
        provider_id="local-fixture",
        model_id="fixture-v1",
    )
    return activity_store.ActivityEntry(
        cluster=cluster,
        summary=summary,
        policy_revisions=("policy-v7",),
        source_fingerprint="a" * 64,
    )


def test_activity_snapshot_round_trips_through_encrypted_owner_only_store(tmp_path: Path) -> None:
    root = tmp_path / "activity"
    store = make_store(root)
    snapshot = activity_store.ActivitySnapshot(entries=(entry(second=True),))

    asyncio.run(store.replace(snapshot))
    restored = asyncio.run(store.load())

    assert restored == snapshot
    persisted = root / "activity-state.lra"
    payload = persisted.read_bytes()
    assert b"reviewed the redacted project notes" not in payload
    assert b"local-fixture" not in payload
    assert b"fixture-v1" not in payload
    assert str(FIRST).encode() not in payload
    assert str(SECOND).encode() not in payload
    assert b"policy-v7" not in payload
    assert oct(root.stat().st_mode & 0o777) == "0o700"
    assert oct(persisted.stat().st_mode & 0o777) == "0o600"


def test_activity_snapshot_replace_is_authoritative(tmp_path: Path) -> None:
    store = make_store(tmp_path / "activity")
    first = activity_store.ActivitySnapshot(entries=(entry(),))
    second = activity_store.ActivitySnapshot(entries=(entry(second=True),))

    asyncio.run(store.replace(first))
    asyncio.run(store.replace(second))

    assert asyncio.run(store.load()) == second


def test_activity_entry_rejects_summary_membership_outside_cluster() -> None:
    cluster = ActivityCluster(
        source_record_ids=(FIRST,),
        started_at=NOW,
        ended_at=NOW,
    )
    summary = ActivitySummary(
        text="bounded evidence",
        source_record_ids=(SECOND,),
        provider_id="local-fixture",
        model_id="fixture-v1",
    )

    with pytest.raises(ValueError, match="membership"):
        activity_store.ActivityEntry(
            cluster=cluster,
            summary=summary,
            policy_revisions=("policy-v7",),
            source_fingerprint="b" * 64,
        )


def test_activity_snapshot_rejects_tampered_ciphertext(tmp_path: Path) -> None:
    root = tmp_path / "activity"
    store = make_store(root)
    asyncio.run(store.replace(activity_store.ActivitySnapshot(entries=(entry(),))))
    persisted = root / "activity-state.lra"
    payload = bytearray(persisted.read_bytes())
    payload[-1] ^= 1
    persisted.write_bytes(payload)

    with pytest.raises(activity_store.ActivityStoreFailure, match="authentication"):
        asyncio.run(store.load())
