from __future__ import annotations

import asyncio
import base64
import json
import math
import os
import stat
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from nacl.exceptions import CryptoError

from local_recall.crypto.bindings import KEY_BYTES, NONCE_BYTES, decrypt, encrypt
from local_recall.domain import (
    EmbeddingRequest,
    EmbeddingResponse,
    KeyHandle,
    KeyPurpose,
    KeyRequest,
    PrivacyClass,
    SecretKeyMaterial,
)
from local_recall.domain._validation import require_aware, require_nonempty
from local_recall.ports.keys import KeyProvider, KeyUnwrapRequest, KeyWrapRequest
from local_recall.ports.providers import EmbeddingProvider

_ACTIVE_NAME = "semantic-index.lri"
_CHECKPOINT_NAME = "semantic-index.rebuild.lri"
_AAD = b"local-recall-semantic-index-v1"
_FORMAT_VERSION = 1
_ALGORITHM = "xchacha20-poly1305-ietf"
_MAX_SNAPSHOT_BYTES = 512 * 1024 * 1024


class IndexFailure(RuntimeError):
    pass


class IndexModelMismatch(IndexFailure):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class IndexDocument:
    record_id: UUID
    captured_at: datetime
    text: str = field(repr=False)
    approved_metadata: tuple[str, ...] = field(repr=False)
    privacy_class: PrivacyClass

    def __post_init__(self) -> None:
        require_aware(self.captured_at, "captured_at")
        require_nonempty(self.text, "text")
        if any(not item for item in self.approved_metadata):
            raise ValueError("approved metadata must not contain empty values")
        if self.privacy_class is not PrivacyClass.REDACTED_CONTENT:
            raise ValueError("semantic indexing requires redacted content")

    def embedding_text(self) -> str:
        return "\n".join((self.text, *self.approved_metadata))


@dataclass(frozen=True, slots=True, repr=False)
class SemanticQuery:
    text: str = field(repr=False)
    start_at: datetime | None = None
    end_at: datetime | None = None
    limit: int = 20

    def __post_init__(self) -> None:
        require_nonempty(self.text, "text")
        if self.start_at is not None:
            require_aware(self.start_at, "start_at")
        if self.end_at is not None:
            require_aware(self.end_at, "end_at")
        if self.start_at is not None and self.end_at is not None and self.end_at <= self.start_at:
            raise ValueError("end_at must be later than start_at")
        if not 1 <= self.limit <= 10_000:
            raise ValueError("limit must be between 1 and 10000")


@dataclass(frozen=True, slots=True)
class SemanticHit:
    record_id: UUID
    captured_at: datetime
    score: float


@dataclass(frozen=True, slots=True)
class IndexManifest:
    model_id: str
    dimensions: int
    record_count: int


@dataclass(frozen=True, slots=True)
class _Entry:
    record_id: UUID
    captured_at: datetime
    vector: tuple[float, ...]


@dataclass(frozen=True, slots=True)
class _Snapshot:
    model_id: str
    dimensions: int
    entries: tuple[_Entry, ...]


class EncryptedSemanticIndex:
    def __init__(self, root: Path, key_provider: KeyProvider) -> None:
        self._root = root
        self._key_provider = key_provider
        self._active = root / _ACTIVE_NAME
        self._checkpoint = root / _CHECKPOINT_NAME
        self._prepare_root()
        self._operation_lock = asyncio.Lock()

    async def manifest(self) -> IndexManifest:
        async with self._operation_lock:
            snapshot = await self._load(self._active)
        if snapshot is None:
            raise IndexFailure("semantic index is not initialized")
        return IndexManifest(snapshot.model_id, snapshot.dimensions, len(snapshot.entries))

    async def add(
        self,
        documents: tuple[IndexDocument, ...],
        provider: EmbeddingProvider,
    ) -> IndexManifest:
        self._validate_documents(documents)
        async with self._operation_lock:
            current = await self._load(self._active)
            if current is None:
                raise IndexFailure("semantic index is not initialized")
            response = await provider.embed(self._embedding_request(documents))
            self._validate_response(response, documents)
            self._require_compatible(current, response)
            entries = {entry.record_id: entry for entry in current.entries}
            entries.update((entry.record_id, entry) for entry in self._entries(documents, response))
            replacement = _Snapshot(
                current.model_id,
                current.dimensions,
                tuple(sorted(entries.values(), key=lambda item: str(item.record_id))),
            )
            await self._save(self._active, replacement)
        return IndexManifest(replacement.model_id, replacement.dimensions, len(replacement.entries))

    async def search(
        self,
        query: SemanticQuery,
        provider: EmbeddingProvider,
    ) -> tuple[SemanticHit, ...]:
        async with self._operation_lock:
            snapshot = await self._load(self._active)
            if snapshot is None:
                return ()
            response = await provider.embed(
                EmbeddingRequest((query.text,), PrivacyClass.REDACTED_CONTENT)
            )
            self._validate_response(response, (query.text,))
            self._require_compatible(snapshot, response)
            query_vector = response.vectors[0]
            hits = [
                SemanticHit(entry.record_id, entry.captured_at, _cosine(query_vector, entry.vector))
                for entry in snapshot.entries
                if _within(query, entry.captured_at)
            ]
        hits.sort(key=lambda item: (-item.score, item.captured_at, str(item.record_id)))
        return tuple(hits[: query.limit])

    async def rebuild(
        self,
        documents: tuple[IndexDocument, ...],
        provider: EmbeddingProvider,
        *,
        batch_size: int = 32,
    ) -> IndexManifest:
        self._validate_documents(documents)
        if batch_size <= 0:
            raise ValueError("batch_size must be positive")
        async with self._operation_lock:
            checkpoint = await self._load(self._checkpoint)
            completed = 0
            entries: list[_Entry] = []
            model_id: str | None = None
            dimensions: int | None = None
            if checkpoint is not None and _matches_prefix(checkpoint, documents):
                completed = len(checkpoint.entries)
                entries.extend(checkpoint.entries)
                model_id = checkpoint.model_id
                dimensions = checkpoint.dimensions

            for offset in range(completed, len(documents), batch_size):
                batch = documents[offset : offset + batch_size]
                response = await provider.embed(self._embedding_request(batch))
                self._validate_response(response, batch)
                if model_id is None:
                    model_id = response.model_id
                    dimensions = len(response.vectors[0])
                elif response.model_id != model_id or len(response.vectors[0]) != dimensions:
                    raise IndexModelMismatch("embedding model or dimension changed during rebuild")
                entries.extend(self._entries(batch, response))
                checkpoint = _Snapshot(model_id, cast(int, dimensions), tuple(entries))
                await self._save(self._checkpoint, checkpoint)

            if model_id is None or dimensions is None:
                raise ValueError("rebuild requires at least one document")
            replacement = _Snapshot(model_id, dimensions, tuple(entries))
            await self._save(self._active, replacement)
            await asyncio.to_thread(self._checkpoint.unlink, missing_ok=True)
        return IndexManifest(model_id, dimensions, len(entries))

    def _prepare_root(self) -> None:
        if self._root.exists():
            info = self._root.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise ValueError("semantic index root must be a real directory")
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise ValueError("semantic index root must be owner-only")
            return
        self._root.mkdir(parents=True, mode=0o700)

    @staticmethod
    def _validate_documents(documents: tuple[IndexDocument, ...]) -> None:
        if not documents:
            raise ValueError("at least one document is required")
        if any(item.privacy_class is not PrivacyClass.REDACTED_CONTENT for item in documents):
            raise ValueError("semantic indexing requires redacted content")
        ids = {item.record_id for item in documents}
        if len(ids) != len(documents):
            raise ValueError("duplicate record IDs are not allowed")

    @staticmethod
    def _embedding_request(documents: tuple[IndexDocument, ...]) -> EmbeddingRequest:
        return EmbeddingRequest(
            tuple(item.embedding_text() for item in documents),
            PrivacyClass.REDACTED_CONTENT,
        )

    @staticmethod
    def _entries(
        documents: tuple[IndexDocument, ...], response: EmbeddingResponse
    ) -> tuple[_Entry, ...]:
        return tuple(
            _Entry(document.record_id, document.captured_at, vector)
            for document, vector in zip(documents, response.vectors, strict=True)
        )

    @staticmethod
    def _validate_response(
        response: EmbeddingResponse,
        inputs: tuple[IndexDocument, ...] | tuple[str, ...],
    ) -> None:
        if len(response.vectors) != len(inputs):
            raise IndexFailure("embedding provider returned the wrong vector count")
        dimension = len(response.vectors[0])
        if dimension <= 0 or any(len(vector) != dimension for vector in response.vectors):
            raise IndexFailure("embedding provider returned inconsistent dimensions")
        if any(any(not math.isfinite(value) for value in vector) for vector in response.vectors):
            raise IndexFailure("embedding provider returned a non-finite value")

    @staticmethod
    def _require_compatible(snapshot: _Snapshot, response: EmbeddingResponse) -> None:
        if response.model_id != snapshot.model_id:
            raise IndexModelMismatch("embedding model does not match the index")
        if len(response.vectors[0]) != snapshot.dimensions:
            raise IndexModelMismatch("embedding dimensions do not match the index")

    async def _save(self, path: Path, snapshot: _Snapshot) -> None:
        plaintext = bytearray(_encode_snapshot(snapshot))
        try:
            payload = await _encrypt_snapshot(bytes(plaintext), self._key_provider)
        finally:
            plaintext[:] = b"\x00" * len(plaintext)
        if len(payload) > _MAX_SNAPSHOT_BYTES:
            raise IndexFailure("semantic index exceeds the snapshot limit")
        await asyncio.to_thread(_atomic_write, path, payload)

    async def _load(self, path: Path) -> _Snapshot | None:
        if not path.exists():
            return None
        payload = await asyncio.to_thread(_read_owner_file, path)
        plaintext = bytearray(await _decrypt_snapshot(payload, self._key_provider))
        try:
            return _decode_snapshot(bytes(plaintext))
        finally:
            plaintext[:] = b"\x00" * len(plaintext)


async def _encrypt_snapshot(plaintext: bytes, provider: KeyProvider) -> bytes:
    key = await provider.active_key(KeyRequest(KeyPurpose.INDEX, create_if_missing=True))
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
        data_key = await provider.unwrap_data_key(KeyUnwrapRequest(key, wrapped, _AAD))
        with data_key:
            return decrypt(ciphertext, _AAD, nonce, data_key.copy_bytes())
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, CryptoError) as exc:
        raise IndexFailure("semantic index authentication failed") from exc


def _encode_snapshot(snapshot: _Snapshot) -> bytes:
    payload = {
        "dimensions": snapshot.dimensions,
        "entries": [
            {
                "captured_at": entry.captured_at.isoformat(),
                "record_id": str(entry.record_id),
                "vector": entry.vector,
            }
            for entry in snapshot.entries
        ],
        "model_id": snapshot.model_id,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _decode_snapshot(payload: bytes) -> _Snapshot:
    try:
        raw = cast(dict[str, Any], json.loads(payload))
        model_id = cast(str, raw["model_id"])
        dimensions = cast(int, raw["dimensions"])
        raw_entries = cast(list[dict[str, Any]], raw["entries"])
        entries = tuple(
            _Entry(
                UUID(item["record_id"]),
                datetime.fromisoformat(item["captured_at"]),
                tuple(float(value) for value in item["vector"]),
            )
            for item in raw_entries
        )
        require_nonempty(model_id, "model_id")
        if dimensions <= 0:
            raise ValueError
        if any(entry.captured_at.tzinfo is None for entry in entries):
            raise ValueError
        if any(len(entry.vector) != dimensions for entry in entries):
            raise ValueError
        return _Snapshot(model_id, dimensions, entries)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise IndexFailure("semantic index payload is invalid") from exc


def _matches_prefix(snapshot: _Snapshot, documents: tuple[IndexDocument, ...]) -> bool:
    if len(snapshot.entries) > len(documents):
        return False
    return all(
        entry.record_id == document.record_id
        for entry, document in zip(snapshot.entries, documents, strict=False)
    )


def _within(query: SemanticQuery, captured_at: datetime) -> bool:
    if query.start_at is not None and captured_at < query.start_at:
        return False
    return query.end_at is None or captured_at < query.end_at


def _cosine(left: tuple[float, ...], right: tuple[float, ...]) -> float:
    numerator = sum(a * b for a, b in zip(left, right, strict=True))
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    if left_norm == 0 or right_norm == 0:
        return 0.0
    return max(0.0, min(1.0, numerator / (left_norm * right_norm)))


def _atomic_write(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(payload)
        written = 0
        while written < len(view):
            written += os.write(descriptor, view[written:])
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
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        raise IndexFailure("semantic index file is unsafe")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise IndexFailure("semantic index file is not owner-only")
    payload = path.read_bytes()
    if not payload or len(payload) > _MAX_SNAPSHOT_BYTES:
        raise IndexFailure("semantic index file has an invalid size")
    return payload


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: object) -> bytes:
    if not isinstance(value, str):
        raise ValueError
    return base64.b64decode(value, validate=True)
