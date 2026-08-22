from __future__ import annotations

import pytest

from local_recall.domain import (
    ModelCapability,
    PrivacyClass,
    ProviderCapabilities,
    ProviderLocation,
)
from local_recall.routing import (
    EgressAuthorization,
    EgressDataClass,
    NoRouteError,
    RoutingMode,
    RoutingPolicy,
    RoutingRequest,
)


def _provider(
    provider_id: str,
    *,
    location: ProviderLocation,
    available: bool = True,
) -> ProviderCapabilities:
    return ProviderCapabilities(
        provider_id=provider_id,
        location=location,
        capabilities=frozenset({ModelCapability.GENERATION}),
        accepted_privacy_classes=frozenset(
            {PrivacyClass.PUBLIC, PrivacyClass.OPERATIONAL_METADATA, PrivacyClass.REDACTED_CONTENT}
        ),
        max_input_bytes=1_048_576,
        supports_vision=False,
        available=available,
    )


@pytest.mark.asyncio
async def test_local_only_selects_local_and_never_remote() -> None:
    policy = RoutingPolicy(RoutingMode.LOCAL_ONLY)
    providers = (
        _provider("remote", location=ProviderLocation.REMOTE),
        _provider("ollama", location=ProviderLocation.LOCAL),
    )

    decision = await policy.route(
        RoutingRequest(
            capability=ModelCapability.GENERATION,
            privacy_class=PrivacyClass.REDACTED_CONTENT,
            data_classes=frozenset({EgressDataClass.REDACTED_TEXT}),
        ),
        providers,
    )

    assert decision.provider_id == "ollama"
    assert decision.location is ProviderLocation.LOCAL
    assert decision.egress_authorization_id is None


@pytest.mark.asyncio
async def test_local_first_does_not_turn_local_failure_into_remote_permission() -> None:
    policy = RoutingPolicy(RoutingMode.LOCAL_FIRST)
    providers = (
        _provider("ollama", location=ProviderLocation.LOCAL, available=False),
        _provider("remote", location=ProviderLocation.REMOTE),
    )

    with pytest.raises(NoRouteError, match="local-unavailable"):
        await policy.route(
            RoutingRequest(
                capability=ModelCapability.GENERATION,
                privacy_class=PrivacyClass.REDACTED_CONTENT,
                data_classes=frozenset({EgressDataClass.REDACTED_TEXT}),
            ),
            providers,
        )


@pytest.mark.asyncio
async def test_privacy_strict_never_accepts_remote_authorization() -> None:
    policy = RoutingPolicy(RoutingMode.PRIVACY_STRICT)
    authorization = EgressAuthorization(
        authorization_id="auth-1",
        provider_id="remote",
        data_classes=frozenset({EgressDataClass.REDACTED_TEXT}),
        max_payload_bytes=4096,
    )

    with pytest.raises(NoRouteError, match="privacy-strict-local-only"):
        await policy.route(
            RoutingRequest(
                capability=ModelCapability.GENERATION,
                privacy_class=PrivacyClass.REDACTED_CONTENT,
                data_classes=frozenset({EgressDataClass.REDACTED_TEXT}),
                authorization=authorization,
            ),
            (_provider("remote", location=ProviderLocation.REMOTE),),
        )


@pytest.mark.asyncio
async def test_remote_explicit_requires_authorization() -> None:
    policy = RoutingPolicy(RoutingMode.REMOTE_EXPLICIT)

    with pytest.raises(NoRouteError, match="egress-authorization-required"):
        await policy.route(
            RoutingRequest(
                capability=ModelCapability.GENERATION,
                privacy_class=PrivacyClass.REDACTED_CONTENT,
                data_classes=frozenset({EgressDataClass.REDACTED_TEXT}),
            ),
            (_provider("remote", location=ProviderLocation.REMOTE),),
        )


@pytest.mark.asyncio
async def test_remote_explicit_binds_provider_and_authorized_data_classes() -> None:
    policy = RoutingPolicy(RoutingMode.REMOTE_EXPLICIT)
    authorization = EgressAuthorization(
        authorization_id="auth-2",
        provider_id="openrouter",
        data_classes=frozenset({EgressDataClass.REDACTED_TEXT, EgressDataClass.APPROVED_METADATA}),
        max_payload_bytes=8192,
    )
    providers = (
        _provider("openai", location=ProviderLocation.REMOTE),
        _provider("openrouter", location=ProviderLocation.REMOTE),
    )

    decision = await policy.route(
        RoutingRequest(
            capability=ModelCapability.GENERATION,
            privacy_class=PrivacyClass.REDACTED_CONTENT,
            data_classes=frozenset(
                {EgressDataClass.REDACTED_TEXT, EgressDataClass.APPROVED_METADATA}
            ),
            authorization=authorization,
        ),
        providers,
    )

    assert decision.provider_id == "openrouter"
    assert decision.location is ProviderLocation.REMOTE
    assert decision.egress_authorization_id == "auth-2"


@pytest.mark.asyncio
async def test_remote_image_is_denied_unless_explicitly_authorized() -> None:
    policy = RoutingPolicy(RoutingMode.REMOTE_EXPLICIT)
    authorization = EgressAuthorization(
        authorization_id="auth-3",
        provider_id="remote",
        data_classes=frozenset({EgressDataClass.REDACTED_TEXT}),
        max_payload_bytes=8192,
    )

    with pytest.raises(NoRouteError, match="egress-data-class-denied"):
        await policy.route(
            RoutingRequest(
                capability=ModelCapability.GENERATION,
                privacy_class=PrivacyClass.REDACTED_CONTENT,
                data_classes=frozenset({EgressDataClass.REDACTED_IMAGE}),
                authorization=authorization,
            ),
            (_provider("remote", location=ProviderLocation.REMOTE),),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "privacy_class",
    [PrivacyClass.RAW_CAPTURE, PrivacyClass.SECRET_MATERIAL],
)
async def test_raw_and_secret_material_are_not_remotely_routable(
    privacy_class: PrivacyClass,
) -> None:
    policy = RoutingPolicy(RoutingMode.REMOTE_EXPLICIT)
    authorization = EgressAuthorization(
        authorization_id="auth-4",
        provider_id="remote",
        data_classes=frozenset({EgressDataClass.REDACTED_TEXT}),
        max_payload_bytes=8192,
    )

    with pytest.raises(NoRouteError, match="privacy-class-denied"):
        await policy.route(
            RoutingRequest(
                capability=ModelCapability.GENERATION,
                privacy_class=privacy_class,
                data_classes=frozenset({EgressDataClass.REDACTED_TEXT}),
                authorization=authorization,
            ),
            (_provider("remote", location=ProviderLocation.REMOTE),),
        )
