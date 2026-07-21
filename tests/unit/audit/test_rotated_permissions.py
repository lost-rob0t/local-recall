from __future__ import annotations

from pathlib import Path

import pytest

from local_recall.audit import (
    AuditFailure,
    AuditFailureCode,
    AuditFileSettings,
    OwnerOnlyAuditFileSink,
)


def test_insecure_rotated_log_fails_closed_at_startup(tmp_path: Path) -> None:
    root = tmp_path / "audit"
    root.mkdir(mode=0o700)
    rotated = root / "audit.0123456789abcdef0123456789abcdef.jsonl"
    rotated.write_text("{}\n")
    rotated.chmod(0o644)

    with pytest.raises(AuditFailure) as captured:
        OwnerOnlyAuditFileSink(AuditFileSettings(root))

    assert captured.value.code is AuditFailureCode.INSECURE_PERMISSIONS
