from __future__ import annotations

import asyncio
from importlib import import_module

from local_recall.domain import (
    ModelCapability,
    PrivacyClass,
    ProviderCapabilities,
    ProviderLocation,
)

providers_domain = import_module("local_recall.domain.providers")
routing = import_module("local_recall.routing")

DomainRoutingRequest = providers_domain.RoutingRequest
EgressAuthorization = routing.EgressAuthorization
EgressDataClass = routing.EgressDataClass
RoutingMode = routing.RoutingMode
RoutingPolicy = routing.RoutingPolicy


def test_routing_policy_accepts_the_repository_public_routing_request() -> None:
    authorization = EgressAuthorization(
        authorization_id="auth-port",
        provider_id="remote-one",
        data_classes=frozenset({EgressDataClass.REDACTED_TEXT}),
        max_payload_bytes=4096,
    )
    request = DomainRoutingRequest(
        capability=ModelCapability.GENERATION,
        privacy_class=PrivacyClass.REDACTED_CONTENT,
        allow_remote=True,
        egress_authorization_id="auth-port",
        data_classes=frozenset({EgressDataClass.REDACTED_TEXT}),
        authorization=authorization,
    )
    provider = ProviderCapabilities(
        provider_id="remote-one",
        location=ProviderLocation.REMOTE,
        capabilities=frozenset({ModelCapability.GENERATION}),
        accepted_privacy_classes=frozenset({PrivacyClass.REDACTED_CONTENT}),
        max_input_bytes=4096,
        supports_vision=False,
    )

    decision = asyncio.run(RoutingPolicy(RoutingMode.REMOTE_EXPLICIT).route(request, (provider,)))

    assert decision.provider_id == "remote-one"
    assert decision.egress_authorization_id == "auth-port"
