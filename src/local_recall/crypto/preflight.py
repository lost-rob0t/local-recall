from __future__ import annotations

from local_recall.domain.crypto import KeyPurpose, KeyRequest
from local_recall.lifecycle.messages import (
    LifecycleFaultCode,
    LifecyclePreflightRequest,
    LifecyclePreflightResult,
)

from .errors import CryptoError
from .router import KeyProviderRouter


class EncryptionLifecyclePreflight:
    def __init__(self, router: KeyProviderRouter) -> None:
        self._router = router

    def check(self, request: LifecyclePreflightRequest) -> LifecyclePreflightResult:
        if request.cancellation.cancelled:
            return LifecyclePreflightResult.failure(LifecycleFaultCode.PREFLIGHT_FAILURE)
        settings = request.configuration.configuration.encryption
        try:
            self._router.select_for_encryption(
                settings,
                KeyRequest(
                    purpose=KeyPurpose.RECORD,
                    create_if_missing=True,
                    reference=settings.key_reference.reference if settings.key_reference else None,
                ),
            )
        except CryptoError:
            return LifecyclePreflightResult.failure(LifecycleFaultCode.ENCRYPTION_UNAVAILABLE)
        return LifecyclePreflightResult.success()
