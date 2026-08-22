from __future__ import annotations

from local_recall.config import RemoteProviderSettings

from .remote import (
    RemoteHttpsTransport,
    RemoteProviderKind,
    RemoteProviderSpec,
    RemoteTransportSettings,
)
from .remote_client import (
    RemoteCredentialProvider,
    RemoteProviderAudit,
    RemoteProviderClient,
    RemoteRequestExecution,
)
from .remote_executor import RemoteExecutionSettings, RemoteRequestExecutor


def compose_remote_provider_client(
    settings: RemoteProviderSettings,
    *,
    credential_provider: RemoteCredentialProvider,
    executor: RemoteRequestExecution | None = None,
    transport_settings: RemoteTransportSettings | None = None,
    execution_settings: RemoteExecutionSettings | None = None,
    audit: RemoteProviderAudit | None = None,
) -> RemoteProviderClient:
    if not settings.enabled:
        raise ValueError("remote provider is disabled")
    if (
        settings.kind is None
        or settings.endpoint is None
        or settings.model_id is None
        or settings.credential_reference is None
    ):
        raise ValueError("remote provider configuration is incomplete")

    spec = RemoteProviderSpec(
        provider_id=settings.provider_id,
        kind=RemoteProviderKind(settings.kind),
        endpoint=settings.endpoint,
        model_id=settings.model_id,
    )
    if executor is None:
        transport = RemoteHttpsTransport(transport_settings or RemoteTransportSettings())
        executor = RemoteRequestExecutor(
            transport,
            execution_settings or RemoteExecutionSettings(),
        )

    return RemoteProviderClient(
        spec=spec,
        credential_reference=settings.credential_reference,
        credential_provider=credential_provider,
        executor=executor,
        audit=audit,
    )
