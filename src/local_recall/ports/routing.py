from __future__ import annotations

from typing import Protocol, runtime_checkable

from local_recall.domain.providers import ProviderCapabilities, RoutingDecision, RoutingRequest


@runtime_checkable
class ModelRoutingPolicy(Protocol):
    @property
    def policy_id(self) -> str: ...

    async def route(
        self,
        request: RoutingRequest,
        providers: tuple[ProviderCapabilities, ...],
    ) -> RoutingDecision: ...
