from __future__ import annotations

import asyncio
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from local_recall.backup.archive import RestoreFailure
from local_recall.backup.engine import BackupEngine
from local_recall.backup.gpg import GpgRecipientCrypter
from local_recall.storage import SQLiteEncryptedStorage
from tests.unit.retention.test_planner import make_record


def _make_key(home: Path) -> str:
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    home.chmod(0o700)
    subprocess.run(
        [
            "gpg",
            "--homedir",
            str(home),
            "--batch",
            "--passphrase",
            "",
            "--quick-generate-key",
            "local-recall-test <backup@test.invalid>",
            "default",
            "default",
            "never",
        ],
        check=True,
        capture_output=True,
        timeout=120,
    )
    output = subprocess.run(
        [
            "gpg",
            "--homedir",
            str(home),
            "--with-colons",
            "--list-keys",
            "backup@test.invalid",
        ],
        check=True,
        capture_output=True,
        timeout=30,
        text=True,
    )
    for line in output.stdout.splitlines():
        if line.startswith("fpr:"):
            return line.split(":")[9]
    raise AssertionError("generated key not found")


def test_gpg_recipient_round_trip(tmp_path: Path) -> None:
    home = tmp_path / "gnupg"
    fingerprint = _make_key(home)
    record = make_record(1, captured_at=datetime(2026, 8, 1, 10, 0, tzinfo=UTC))
    source = SQLiteEncryptedStorage(
        tmp_path / "source", quota_bytes=100_000_000, max_blob_bytes=1_000_000
    )
    from tests.unit.retention.test_planner import make_envelope

    asyncio.run(source.put(make_envelope(record)))
    crypter = GpgRecipientCrypter(recipient=fingerprint, gnupg_home=str(home))
    engine = BackupEngine(source_storage=source, crypter=crypter)
    archive_path = tmp_path / "backup.lrb.gpg"

    export = asyncio.run(engine.export(archive_path))
    assert export.record_count == 1
    assert not archive_path.read_bytes().startswith(b"LRBACKUP")

    target = SQLiteEncryptedStorage(
        tmp_path / "target", quota_bytes=100_000_000, max_blob_bytes=1_000_000
    )
    restore = asyncio.run(engine.restore(archive_path, target))
    assert restore.restored_count == 1
    assert asyncio.run(target.get(record.record_id)) is not None


def test_wrong_recipient_archive_fails_safely(tmp_path: Path) -> None:
    home = tmp_path / "gnupg"
    fingerprint = _make_key(home)
    record = make_record(1, captured_at=datetime(2026, 8, 1, 10, 0, tzinfo=UTC))
    source = SQLiteEncryptedStorage(
        tmp_path / "source", quota_bytes=100_000_000, max_blob_bytes=1_000_000
    )
    from tests.unit.retention.test_planner import make_envelope

    asyncio.run(source.put(make_envelope(record)))
    crypter = GpgRecipientCrypter(recipient=fingerprint, gnupg_home=str(home))
    engine = BackupEngine(source_storage=source, crypter=crypter)
    archive_path = tmp_path / "backup.lrb.gpg"
    asyncio.run(engine.export(archive_path))
    target = SQLiteEncryptedStorage(
        tmp_path / "target", quota_bytes=100_000_000, max_blob_bytes=1_000_000
    )

    other_home = tmp_path / "other-gnupg"
    other_fingerprint = _make_key(other_home)
    other_crypter = GpgRecipientCrypter(recipient=other_fingerprint, gnupg_home=str(other_home))
    other_engine = BackupEngine(source_storage=source, crypter=other_crypter)

    with pytest.raises(RestoreFailure, match="failed"):
        asyncio.run(other_engine.restore(archive_path, target))
    assert asyncio.run(target.stats()).ready_records == 0
