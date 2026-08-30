"""Bounded, content-free backup archive container."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from local_recall.domain.crypto import EncryptedRecordEnvelope
from local_recall.storage.codec import decode_envelope, encode_envelope
from local_recall.storage.errors import StorageFailure

_MAGIC = b"LRBACKUP"
_FORMAT_VERSION = 1
_HEADER_PREFIX = struct.Struct(">8sBHI")
_MAX_MANIFEST_BYTES = 1 << 20
_DIGEST_BYTES = 32


class RestoreFailure(RuntimeError):
    """Sanitized restore failure."""


@dataclass(frozen=True, slots=True)
class ArchiveManifest:
    format_version: int
    schema_version: int
    created_at: str
    record_count: int
    body_digest: str

    def to_dict(self) -> dict[str, object]:
        return {
            "created_at": self.created_at,
            "format_version": self.format_version,
            "record_count": self.record_count,
            "schema_version": self.schema_version,
            "body_digest": self.body_digest,
        }


@dataclass(frozen=True, slots=True)
class BackupArchive:
    manifest: ArchiveManifest
    envelopes: tuple[EncryptedRecordEnvelope, ...]

    @classmethod
    def write(
        cls,
        path: Path,
        *,
        envelopes: tuple[EncryptedRecordEnvelope, ...],
        created_at: str,
        schema_version: int,
        max_blob_bytes: int,
    ) -> None:
        body = bytearray()
        for envelope in envelopes:
            blob = encode_envelope(envelope)
            body.extend(struct.pack(">I", len(blob)))
            body.extend(blob)
        digest = hashlib.sha256(bytes(body)).hexdigest()
        manifest = {
            "body_digest": digest,
            "created_at": created_at,
            "format_version": _FORMAT_VERSION,
            "record_count": len(envelopes),
            "schema_version": schema_version,
        }
        manifest_bytes = _canonical_json(manifest)
        header = _HEADER_PREFIX.pack(_MAGIC, _FORMAT_VERSION, len(manifest_bytes), len(body))
        with open(path, "wb") as handle:
            handle.write(header)
            handle.write(manifest_bytes)
            handle.write(bytes(body))

    @classmethod
    def read(
        cls,
        path: Path,
        *,
        max_blob_bytes: int,
        expected_schema_version: int | None = None,
    ) -> BackupArchive:
        data = path.read_bytes()
        if len(data) < _HEADER_PREFIX.size:
            raise RestoreFailure("archive is truncated")
        magic, version, manifest_len, _body_len = _HEADER_PREFIX.unpack_from(data)
        if magic != _MAGIC or version != _FORMAT_VERSION:
            raise RestoreFailure("archive header is invalid")
        offset = _HEADER_PREFIX.size
        if manifest_len > _MAX_MANIFEST_BYTES or offset + manifest_len > len(data):
            raise RestoreFailure("archive manifest is invalid")
        manifest_raw = _load_manifest(data[offset : offset + manifest_len])
        manifest = ArchiveManifest(
            format_version=_int_field(manifest_raw, "format_version"),
            schema_version=_int_field(manifest_raw, "schema_version"),
            created_at=_str_field(manifest_raw, "created_at"),
            record_count=_int_field(manifest_raw, "record_count"),
            body_digest=_str_field(manifest_raw, "body_digest"),
        )
        if (
            expected_schema_version is not None
            and manifest.schema_version != expected_schema_version
        ):
            raise RestoreFailure("archive schema version is incompatible")
        body = data[offset + manifest_len :]
        if len(body) < _DIGEST_BYTES * 0:
            raise RestoreFailure("archive body is truncated")
        if hashlib.sha256(body).hexdigest() != manifest.body_digest:
            raise RestoreFailure("archive body digest mismatch")
        envelopes: list[EncryptedRecordEnvelope] = []
        cursor = 0
        while cursor < len(body):
            if cursor + 4 > len(body):
                raise RestoreFailure("archive body is truncated")
            (blob_len,) = struct.unpack_from(">I", body, cursor)
            cursor += 4
            if cursor + blob_len > len(body):
                raise RestoreFailure("archive body is truncated")
            blob = bytes(body[cursor : cursor + blob_len])
            try:
                envelopes.append(decode_envelope(blob, max_blob_bytes=max_blob_bytes))
            except StorageFailure as exc:
                raise RestoreFailure("archive record is corrupt") from exc
            cursor += blob_len
        if len(envelopes) != manifest.record_count:
            raise RestoreFailure("archive record count mismatch")
        return cls(manifest=manifest, envelopes=tuple(envelopes))


def _canonical_json(payload: dict[str, str | int]) -> bytes:
    import json

    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _int_field(values: dict[str, object], key: str) -> int:
    value = values[key]
    if not isinstance(value, int) or isinstance(value, bool):
        raise RestoreFailure("archive manifest is invalid")
    return value


def _str_field(values: dict[str, object], key: str) -> str:
    value = values[key]
    if not isinstance(value, str):
        raise RestoreFailure("archive manifest is invalid")
    return value


def _load_manifest(raw: bytes) -> dict[str, object]:
    import json

    try:
        loaded = cast(dict[str, object], json.loads(raw.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RestoreFailure("archive manifest is invalid") from exc
    required = {"body_digest", "created_at", "format_version", "record_count", "schema_version"}
    if set(loaded) != required:
        raise RestoreFailure("archive manifest is invalid")
    return loaded
