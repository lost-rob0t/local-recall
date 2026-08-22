from __future__ import annotations

import asyncio
import base64
import json
import os
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from nacl.exceptions import CryptoError

from local_recall.crypto.bindings import KEY_BYTES, NONCE_BYTES, decrypt, encrypt
from local_recall.domain import KeyHandle, KeyPurpose, KeyRequest, SecretKeyMaterial
from local_recall.domain._validation import require_nonempty
from local_recall.ports.keys import KeyProvider, KeyUnwrapRequest, KeyWrapRequest

from .clustering import ActivityCluster
from .summaries import ActivitySummary

_ACTIVE_NAME = "activity-state.lra"
_AAD = b"local-recall-activity-state-v1"
_ALGORITHM = "xchacha20-poly1305-ietf"
_FORMAT_VERSION = 1
_MAX_ENTRIES = 100_000
_MAX_POLICY_REVISIONS = 64
_MAX_POLICY_REVISION_LENGTH = 256
_MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024


class ActivityStoreFailure(RuntimeError):
    """Sanitized activity-store failure."""


@dataclass(frozen=True, slots=True, repr=False)
class ActivityEntry:
    cluster: ActivityCluster
    summary: ActivitySummary | None
    policy_revisions: tuple[str, ...]
    source_fingerprint: str

    def __post_init__(self) -> None:
        if not self.policy_revisions:
            raise ValueError("activity entry requires policy revisions")
        if len(self.policy_revisions) > _MAX_POLICY_REVISIONS:
            raise ValueError("activity entry exceeds policy revision limit")
        if len(set(self.policy_revisions)) != len(self.policy_revisions):
            raise ValueError("activity entry policy revisions must be unique")
        for revision in self.policy_revisions:
            require_nonempty(revision, "policy_revision")
            if len(revision) > _MAX_POLICY_REVISION_LENGTH:
                raise ValueError("policy_revision exceeds maximum length")
        if len(self.source_fingerprint) != 64:
            raise ValueError("source_fingerprint must be a SHA-256 hex digest")
        try:
            fingerprint = bytes.fromhex(self.source_fingerprint)
        except ValueError as exc:
            raise ValueError("source_fingerprint must be a SHA-256 hex digest") from exc
        if len(fingerprint) != 32 or self.source_fingerprint != self.source_fingerprint.lower():
            raise ValueError("source_fingerprint must be a SHA-256 hex digest")
        if self.summary is not None and not set(self.summary.source_record_ids).issubset(
            self.cluster.source_record_ids
        ):
            raise ValueError("activity summary membership must be inside the cluster")

    def __repr__(self) -> str:
        return (
            "ActivityEntry("
            f"source_count={len(self.cluster.source_record_ids)}, "
            f"has_summary={self.summary is not None}, "
            f"policy_revision_count={len(self.policy_revisions)}, "
            "source_fingerprint=redacted)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class ActivitySnapshot:
    entries: tuple[ActivityEntry, ...]

    def __post_init__(self) -> None:
        if len(self.entries) > _MAX_ENTRIES:
            raise ValueError("activity snapshot exceeds entry limit")
        source_ids: list[UUID] = []
        for entry in self.entries:
            source_ids.extend(entry.cluster.source_record_ids)
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("activity snapshot source membership must be unique")

    def __repr__(self) -> str:
        return f"ActivitySnapshot(entry_count={len(self.entries)})"


class EncryptedActivityStore:
    def __init__(self, root: Path, key_provider: KeyProvider) -> None:
        self._root = root
        self._key_provider = key_provider
        self._active = root / _ACTIVE_NAME
        self._prepare_root()
        self._operation_lock = asyncio.Lock()

    def __repr__(self) -> str:
        return "EncryptedActivityStore(root=redacted)"

    async def replace(self, snapshot: ActivitySnapshot) -> None:
        plaintext = bytearray(_encode_snapshot(snapshot))
        try:
            payload = await _encrypt_snapshot(bytes(plaintext), self._key_provider)
        finally:
            plaintext[:] = b"\x00" * len(plaintext)
        if len(payload) > _MAX_SNAPSHOT_BYTES:
            raise ActivityStoreFailure("activity snapshot exceeds size limit")
        async with self._operation_lock:
            await asyncio.to_thread(_atomic_write, self._active, payload)

    async def load(self) -> ActivitySnapshot | None:
        async with self._operation_lock:
            if not self._active.exists():
                return None
            payload = await asyncio.to_thread(_read_owner_file, self._active)
            plaintext = bytearray(await _decrypt_snapshot(payload, self._key_provider))
            try:
                return _decode_snapshot(bytes(plaintext))
            finally:
                plaintext[:] = b"\x00" * len(plaintext)

    def _prepare_root(self) -> None:
        if self._root.exists():
            info = self._root.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise ValueError("activity store root must be a real directory")
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise ValueError("activity store root must be owner-only")
            return
        self._root.mkdir(parents=True, mode=0o700)


async def _encrypt_snapshot(plaintext: bytes, provider: KeyProvider) -> bytes:
    key = await provider.active_key(KeyRequest(KeyPurpose.SUMMARY, create_if_missing=True))
    with SecretKeyMaterial.random(KEY_BYTES) as data_key:
        wrapped = await provider.wrap_data_key(KeyWrapRequest(key, data_key, _AAD))
        nonce = os.urandom(NONCE_BYTES)
        ciphertext = encrypt(plaintext, _AAD, nonce, data_key.copy_bytes())
    payload = {
        "algorithm": _ALGORITHM,
        "ciphertext": _b64(ciphertext),
        "format_version": _FORMAT_VERSION,
        "key": {"id": key.key_id, "provider": key.provider_id, "version": key.version},
        "nonce": _b64(nonce),
        "wrapped_data_key": _b64(wrapped),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


async def _decrypt_snapshot(payload: bytes, provider: KeyProvider) -> bytes:
    try:
        raw = cast(dict[str, Any], json.loads(payload))
        if raw["format_version"] != _FORMAT_VERSION or raw["algorithm"] != _ALGORITHM:
            raise ValueError
        raw_key = cast(dict[str, Any], raw["key"])
        key = KeyHandle(raw_key["id"], raw_key["provider"], raw_key["version"])
        wrapped = _unb64(raw["wrapped_data_key"])
        nonce = _unb64(raw["nonce"])
        ciphertext = _unb64(raw["ciphertext"])
        if len(nonce) != NONCE_BYTES:
            raise ValueError
        data_key = await provider.unwrap_data_key(KeyUnwrapRequest(key, wrapped, _AAD))
        with data_key:
            return decrypt(ciphertext, _AAD, nonce, data_key.copy_bytes())
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, CryptoError) as exc:
        raise ActivityStoreFailure("activity snapshot authentication failed") from exc


def _encode_snapshot(snapshot: ActivitySnapshot) -> bytes:
    payload = {
        "entries": [
            {
                "cluster": {
                    "ended_at": entry.cluster.ended_at.isoformat(),
                    "source_record_ids": [
                        str(source_id) for source_id in entry.cluster.source_record_ids
                    ],
                    "started_at": entry.cluster.started_at.isoformat(),
                },
                "policy_revisions": entry.policy_revisions,
                "source_fingerprint": entry.source_fingerprint,
                "summary": (
                    None
                    if entry.summary is None
                    else {
                        "model_id": entry.summary.model_id,
                        "provider_id": entry.summary.provider_id,
                        "source_record_ids": [
                            str(source_id) for source_id in entry.summary.source_record_ids
                        ],
                        "text": entry.summary.text,
                    }
                ),
            }
            for entry in snapshot.entries
        ]
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _decode_snapshot(payload: bytes) -> ActivitySnapshot:
    try:
        raw = cast(dict[str, Any], json.loads(payload))
        if set(raw) != {"entries"}:
            raise ValueError
        raw_entries = cast(list[dict[str, Any]], raw["entries"])
        entries = tuple(_decode_entry(item) for item in raw_entries)
        return ActivitySnapshot(entries=entries)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ActivityStoreFailure("activity snapshot payload is invalid") from exc


def _decode_entry(raw: dict[str, Any]) -> ActivityEntry:
    if set(raw) != {"cluster", "policy_revisions", "source_fingerprint", "summary"}:
        raise ValueError
    raw_cluster = cast(dict[str, Any], raw["cluster"])
    if set(raw_cluster) != {"ended_at", "source_record_ids", "started_at"}:
        raise ValueError
    cluster = ActivityCluster(
        source_record_ids=tuple(
            UUID(value) for value in cast(list[str], raw_cluster["source_record_ids"])
        ),
        started_at=datetime.fromisoformat(cast(str, raw_cluster["started_at"])),
        ended_at=datetime.fromisoformat(cast(str, raw_cluster["ended_at"])),
    )
    raw_summary = raw["summary"]
    summary: ActivitySummary | None = None
    if raw_summary is not None:
        raw_summary = cast(dict[str, Any], raw_summary)
        if set(raw_summary) != {"model_id", "provider_id", "source_record_ids", "text"}:
            raise ValueError
        summary = ActivitySummary(
            text=cast(str, raw_summary["text"]),
            source_record_ids=tuple(
                UUID(value) for value in cast(list[str], raw_summary["source_record_ids"])
            ),
            provider_id=cast(str, raw_summary["provider_id"]),
            model_id=cast(str, raw_summary["model_id"]),
        )
    return ActivityEntry(
        cluster=cluster,
        summary=summary,
        policy_revisions=tuple(cast(list[str], raw["policy_revisions"])),
        source_fingerprint=cast(str, raw["source_fingerprint"]),
    )


def _atomic_write(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise OSError("activity snapshot write made no progress")
            written += count
        os.fsync(descriptor)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _read_owner_file(path: Path) -> bytes:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ActivityStoreFailure("activity snapshot must be a regular file")
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ActivityStoreFailure("activity snapshot must be owner-only")
    if info.st_size > _MAX_SNAPSHOT_BYTES:
        raise ActivityStoreFailure("activity snapshot exceeds size limit")
    return path.read_bytes()


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: object) -> bytes:
    if not isinstance(value, str):
        raise ValueError
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError from exc
