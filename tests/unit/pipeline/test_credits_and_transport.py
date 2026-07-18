from __future__ import annotations

import threading

import zmq

from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.pipeline import CreditLedger, PipelineLimits, PipelineOwnershipError
from local_recall.pipeline.transport import EndpointRegistry, make_pull_socket, make_push_socket


def test_credit_ledger_is_hard_bounded_per_edge() -> None:
    ledger = CreditLedger(2)
    generation = CaptureGeneration(1)

    assert ledger.try_acquire(generation)
    assert ledger.try_acquire(generation)
    assert not ledger.try_acquire(generation)
    assert ledger.in_use == 2

    ledger.release(generation)
    assert ledger.try_acquire(generation)


def test_raw_endpoint_registry_never_exposes_ipc_or_tcp() -> None:
    registry = EndpointRegistry()

    assert all(endpoint.address.startswith("inproc://") for endpoint in registry.all())
    assert all("ipc://" not in endpoint.address for endpoint in registry.all())
    assert all("tcp://" not in endpoint.address for endpoint in registry.all())


def test_socket_options_and_thread_ownership() -> None:
    context: zmq.Context[zmq.Socket[bytes]] = zmq.Context()
    endpoint = EndpointRegistry().ingress
    pull = make_pull_socket(context, endpoint, capacity=1, limits=PipelineLimits())
    push = make_push_socket(context, endpoint, capacity=1, limits=PipelineLimits())
    errors: list[BaseException] = []

    def misuse() -> None:
        try:
            push.send_multipart([b"header", b"payload"])
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=misuse)
    thread.start()
    thread.join()

    assert len(errors) == 1
    assert isinstance(errors[0], PipelineOwnershipError)
    assert pull.raw.getsockopt(zmq.RCVHWM) == 1
    assert push.raw.getsockopt(zmq.SNDHWM) == 1
    assert push.raw.getsockopt(zmq.LINGER) == 0

    push.close()
    pull.close()
    context.destroy(linger=0)
