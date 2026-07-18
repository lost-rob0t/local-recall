from __future__ import annotations

from local_recall.pipeline.cancellation import PipelineCancellationToken
from local_recall.pipeline.models import EncryptedStageItem, RedactedStageItem

from .cipher import RecordCipher
from .codec import encode_envelope
from .errors import CryptoError


class EncryptionStageProcessor:
    def __init__(self, cipher: RecordCipher) -> None:
        self._cipher = cipher

    def process(
        self,
        item: RedactedStageItem,
        cancellation: PipelineCancellationToken,
    ) -> EncryptedStageItem:
        if cancellation.cancelled:
            raise CryptoError("encryption_cancelled", record_id=item.record_id)
        envelope = self._cipher.encrypt(item)
        if cancellation.cancelled:
            raise CryptoError("encryption_cancelled", record_id=item.record_id)
        return EncryptedStageItem(
            record_id=item.record_id,
            generation=item.generation,
            configuration_revision=item.configuration_revision,
            deadline_monotonic_ns=item.deadline_monotonic_ns,
            frames=encode_envelope(envelope),
        )
