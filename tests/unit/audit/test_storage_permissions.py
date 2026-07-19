from __future__ import annotations

from pathlib import Path

import pytest

from local_recall.audit import (
    AuditFailure,
    AuditFailureCode,
    RuntimeHardener,
    validate_owner_only_storage_tree,
)


def test_valid_owner_only_storage_tree_passes(tmp_path: Path) -> None:
    root = tmp_path / "storage"
    blobs = root / "blobs"
    root.mkdir(mode=0o700)
    blobs.mkdir(mode=0o700)
    blob = blobs / "fixture.lre"
    blob.write_bytes(b"encrypted")
    blob.chmod(0o600)

    report = validate_owner_only_storage_tree(root)

    assert report.directories == 2
    assert report.files == 1


def test_insecure_storage_directory_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "storage"
    root.mkdir(mode=0o755)
    root.chmod(0o755)

    with pytest.raises(AuditFailure) as captured:
        validate_owner_only_storage_tree(root)

    assert captured.value.code is AuditFailureCode.INSECURE_PERMISSIONS


def test_insecure_storage_file_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "storage"
    root.mkdir(mode=0o700)
    catalog = root / "catalog.sqlite3"
    catalog.write_bytes(b"catalog")
    catalog.chmod(0o644)

    with pytest.raises(AuditFailure) as captured:
        validate_owner_only_storage_tree(root)

    assert captured.value.code is AuditFailureCode.INSECURE_PERMISSIONS


def test_runtime_hardener_disables_crash_outputs_before_storage_check(
    tmp_path: Path,
) -> None:
    root = tmp_path / "storage"
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    limits = (1, 1)
    disabled: list[bool] = []

    def set_limits(resource_id: int, value: tuple[int, int]) -> None:
        nonlocal limits
        del resource_id
        limits = value

    with pytest.raises(AuditFailure) as captured:
        RuntimeHardener(
            core_resource_id=4,
            set_limits=set_limits,
            get_limits=lambda resource_id: limits,
            set_umask=lambda value: 0,
            disable_fault_handler=lambda: disabled.append(True),
        ).apply(storage_roots=(root,))

    assert captured.value.code is AuditFailureCode.INSECURE_PERMISSIONS
    assert limits == (0, 0)
    assert disabled == [True]
