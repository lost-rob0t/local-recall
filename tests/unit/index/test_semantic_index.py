from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from local_recall.crypto import OSKeyringProvider
from local_recall.domain import (
    EmbeddingRequest,
    EmbeddingResponse,
    ModelCapability,
    PrivacyClass,
    ProviderCapabilities,
    ProviderLocation,
)
from local_recall.index import (
    EncryptedSemanticIndex,
    IndexDocument,
    IndexModelMismatch,
    SemanticQuery,
)


class MemoryKeyringBackend:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.values.pop((service, username), None)


class FixedEmbeddingProvider:
    def __init__(self, model_id: str = "model-v1", dimensions: int = 3) -> None:
        self.model_id = model_id
        self.dimensions = dimensions
        self.calls: list[tuple[str, ...]] = []
        self.block_after: int | None = None
        self.blocked = asyncio.Event()

    async def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider_id="fixture",
            location=ProviderLocation.LOCAL,
            capabilities=frozenset({ModelCapability.EMBEDDING}),
            accepted_privacy_classes=frozenset({PrivacyClass.REDACTED_CONTENT}),
            max_input_bytes=1024,
            supports_vision=False,
        )

    async def embed(self, request: EmbeddingRequest) -> EmbeddingResponse:
        assert request.privacy_class is PrivacyClass.REDACTED_CONTENT
        self.calls.append(request.inputs)
        if self.block_after is not None and len(self.calls) > self.block_after:
            self.blocked.set()
            await asyncio.Event().wait()
        vectors = tuple(self._vector(value) for value in request.inputs)
        return EmbeddingResponse("fixture", self.model_id, vectors)

    def _vector(self, value: str) -> tuple[float, ...]:
        base = {
            "alpha": (1.0, 0.0, 0.0),
            "beta": (0.0, 1.0, 0.0),
            "gamma": (0.0, 0.0, 1.0),
        }.get(value, (1.0, 0.0, 0.0))
        return base[: self.dimensions]


NOW = datetime(2026, 7, 22, 8, 0, tzinfo=UTC)


def document(number: int, text: str, *, minutes: int = 0) -> IndexDocument:
    return IndexDocument(
        record_id=UUID(f"00000000-0000-4000-8000-{number:012d}"),
        captured_at=NOW + timedelta(minutes=minutes),
        text=text,
        approved_metadata=(),
        privacy_class=PrivacyClass.REDACTED_CONTENT,
    )


def make_index(path: Path) -> EncryptedSemanticIndex:
    return EncryptedSemanticIndex(path, OSKeyringProvider(MemoryKeyringBackend()))


def test_encrypted_index_supports_time_bounded_semantic_search(tmp_path: Path) -> None:
    index = make_index(tmp_path / "index")
    provider = FixedEmbeddingProvider()
    documents = (
        document(1, "alpha", minutes=0),
        document(2, "beta", minutes=10),
        document(3, "alpha", minutes=20),
    )
    asyncio.run(index.rebuild(documents, provider, batch_size=2))

    hits = asyncio.run(
        index.search(
            SemanticQuery(
                text="alpha",
                start_at=NOW + timedelta(minutes=15),
                end_at=NOW + timedelta(minutes=30),
                limit=5,
            ),
            provider,
        )
    )

    assert tuple(hit.record_id for hit in hits) == (documents[2].record_id,)
    assert abs(hits[0].score - 1.0) < 1e-12


def test_persisted_index_contains_no_document_text_or_record_ids(tmp_path: Path) -> None:
    root = tmp_path / "index"
    index = make_index(root)
    provider = FixedEmbeddingProvider()
    seeded = document(123, "seeded-window-title-and-ocr")
    asyncio.run(index.rebuild((seeded,), provider))

    persisted = b"".join(path.read_bytes() for path in root.rglob("*") if path.is_file())

    assert seeded.text.encode() not in persisted
    assert str(seeded.record_id).encode() not in persisted
    assert oct((root / "semantic-index.lri").stat().st_mode & 0o777) == "0o600"


def test_model_or_dimension_mismatch_is_rejected_before_index_change(tmp_path: Path) -> None:
    index = make_index(tmp_path / "index")
    original = FixedEmbeddingProvider()
    asyncio.run(index.rebuild((document(1, "alpha"),), original))

    with pytest.raises(IndexModelMismatch):
        asyncio.run(index.add((document(2, "beta"),), FixedEmbeddingProvider("model-v2")))
    with pytest.raises(IndexModelMismatch):
        asyncio.run(index.add((document(2, "beta"),), FixedEmbeddingProvider(dimensions=2)))

    assert (
        asyncio.run(index.search(SemanticQuery("alpha"), original))[0].record_id
        == document(1, "alpha").record_id
    )


def test_cancelled_rebuild_leaves_encrypted_checkpoint_and_active_index_unchanged(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        root = tmp_path / "index"
        index = make_index(root)
        current = FixedEmbeddingProvider()
        original = document(1, "alpha")
        await index.rebuild((original,), current)

        migration = FixedEmbeddingProvider("model-v2")
        migration.block_after = 1
        task = asyncio.create_task(
            index.rebuild((document(2, "beta"), document(3, "gamma")), migration, batch_size=1)
        )
        await migration.blocked.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        checkpoint = root / "semantic-index.rebuild.lri"
        assert checkpoint.exists()
        assert b"beta" not in checkpoint.read_bytes()
        hits = await index.search(SemanticQuery("alpha"), current)
        assert tuple(hit.record_id for hit in hits) == (original.record_id,)

        await index.rebuild(
            (document(2, "beta"), document(3, "gamma")),
            FixedEmbeddingProvider("model-v2"),
            batch_size=1,
        )
        assert not checkpoint.exists()
        assert (await index.manifest()).model_id == "model-v2"

    asyncio.run(exercise())


def test_raw_document_is_rejected_before_embedding(tmp_path: Path) -> None:
    provider = FixedEmbeddingProvider()
    with pytest.raises(ValueError, match="redacted"):
        IndexDocument(
            record_id=UUID("00000000-0000-4000-8000-000000000001"),
            captured_at=NOW,
            text="raw",
            approved_metadata=(),
            privacy_class=PrivacyClass.RAW_CAPTURE,
        )

    assert provider.calls == []
