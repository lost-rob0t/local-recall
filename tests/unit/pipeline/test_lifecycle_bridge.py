from __future__ import annotations

from typing import Any, cast
from uuid import uuid4

import pykka

from local_recall.lifecycle.actor import LifecycleActor
from local_recall.lifecycle.messages import FaultCapture, LifecycleFaultCode
from local_recall.pipeline import (
    LifecyclePipelineFaultSink,
    PipelineFaultCode,
    PipelineFaultEvent,
    PipelineStage,
)


class RecordingActorRef:
    def __init__(self) -> None:
        self.messages: list[object] = []

    def tell(self, message: object) -> None:
        self.messages.append(message)


def test_worker_fault_bridge_requests_authoritative_lifecycle_fault() -> None:
    fake = RecordingActorRef()
    sink = LifecyclePipelineFaultSink(cast(pykka.ActorRef[LifecycleActor], cast(Any, fake)))

    sink.emit(
        PipelineFaultEvent(
            record_id=uuid4(),
            stage=PipelineStage.RAW,
            fault_code=PipelineFaultCode.PROCESSOR_FAILURE,
        )
    )

    assert len(fake.messages) == 1
    assert isinstance(fake.messages[0], FaultCapture)
    assert fake.messages[0].fault_code is LifecycleFaultCode.ACTOR_FAILURE
