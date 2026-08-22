from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from local_recall.config import CredentialReference
from local_recall.routing import ApprovedEgressPayload

from .remote import (
    RemoteHttpRequest,
    RemoteProviderSpec,
    RemoteRequestBuilder,
    RemoteRequestError,
    ResolvedCredential,
)


class RemoteCredentialProvider(Protocol):
    def resolve(self, reference: CredentialReference) -> ResolvedCredential: ...


class RemoteRequestExecution(Protocol):
    async def execute(self, request: RemoteHttpRequest) -> Mapping[str, object]: ...


class RemoteProviderClient:
    def __init__(
        self,
        *,
        spec: RemoteProviderSpec,
        credential_reference: CredentialReference,
        credential_provider: RemoteCredentialProvider,
        executor: RemoteRequestExecution,
        builder: RemoteRequestBuilder | None = None,
    ) -> None:
        self._spec = spec
        self._credential_reference = credential_reference
        self._credential_provider = credential_provider
        self._executor = executor
        self._builder = builder or RemoteRequestBuilder()

    @property
    def provider_id(self) -> str:
        return self._spec.provider_id

    async def execute(self, approved: ApprovedEgressPayload) -> Mapping[str, object]:
        if approved.provider_id != self._spec.provider_id:
            raise RemoteRequestError("provider-authorization-mismatch")

        credential = self._credential_provider.resolve(self._credential_reference)
        request = self._builder.build(self._spec, approved, credential)
        return await self._executor.execute(request)
