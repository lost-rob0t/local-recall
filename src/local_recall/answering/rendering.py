"""Deterministic rendering for canonical cited answers."""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from local_recall.activity.clustering import ActivityCluster

from .models import AnswerCitation, AnswerClaim, AnswerClaimKind, AnswerMode, CitedAnswer

_INSUFFICIENT_EVIDENCE = "Insufficient evidence."


def render_answer(answer: CitedAnswer, *, clusters: Sequence[ActivityCluster] = ()) -> str:
    """Render claims with Local Recall-owned record/time/activity citations."""

    if answer.insufficient_evidence:
        return _INSUFFICIENT_EVIDENCE

    claims = answer.claims
    if answer.mode is AnswerMode.TIMELINE:
        claims = tuple(sorted(claims, key=_claim_sort_key))

    cluster_index = _cluster_index(clusters)
    return "\n".join(_render_claim(claim, cluster_index=cluster_index) for claim in claims)


def _claim_sort_key(claim: AnswerClaim) -> tuple[object, str]:
    return (min(citation.captured_at for citation in claim.citations), claim.text)


def _cluster_index(clusters: Sequence[ActivityCluster]) -> dict[UUID, ActivityCluster | None]:
    index: dict[UUID, ActivityCluster | None] = {}
    for cluster in clusters:
        for record_id in cluster.source_record_ids:
            if record_id in index:
                index[record_id] = None
            else:
                index[record_id] = cluster
    return index


def _render_claim(
    claim: AnswerClaim,
    *,
    cluster_index: dict[UUID, ActivityCluster | None],
) -> str:
    kind = "Observed" if claim.kind is AnswerClaimKind.OBSERVED else "Inference"
    citations = "; ".join(
        _render_citation(citation, cluster=cluster_index.get(citation.record_id))
        for citation in claim.citations
    )
    return f"{kind}: {claim.text} [{citations}]"


def _render_citation(citation: AnswerCitation, *, cluster: ActivityCluster | None) -> str:
    base = f"record {citation.record_id} @ {citation.captured_at.isoformat()}"
    if cluster is None:
        return base
    return f"{base}; activity {cluster.started_at.isoformat()}..{cluster.ended_at.isoformat()}"
