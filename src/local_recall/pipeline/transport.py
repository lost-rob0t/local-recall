from __future__ import annotations

import threading
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, cast
from uuid import uuid4

import zmq

from .errors import PipelineOwnershipError
from .models import PipelineLimits, PipelineStage


class _MultipartSocket(Protocol):
    def send_multipart(
        self,
        msg_parts: Sequence[bytes],
        flags: int = 0,
        copy: bool = True,
        track: bool = False,
    ) -> object | None: ...

    def recv_multipart(self, flags: int = 0, copy: bool = True) -> list[bytes]: ...


@dataclass(frozen=True, slots=True)
class PipelineEndpoint:
    source: PipelineStage | None
    destination: PipelineStage
    address: str

    def __post_init__(self) -> None:
        if not self.address.startswith("inproc://"):
            raise ValueError("raw pipeline endpoints must use inproc transport")


class EndpointRegistry:
    def __init__(self) -> None:
        opaque = uuid4().hex
        self.ingress = PipelineEndpoint(None, PipelineStage.RAW, f"inproc://lr-{opaque}-raw")
        self.raw_to_analyzed = PipelineEndpoint(
            PipelineStage.RAW,
            PipelineStage.ANALYZED,
            f"inproc://lr-{opaque}-analyzed",
        )
        self.analyzed_to_redacted = PipelineEndpoint(
            PipelineStage.ANALYZED,
            PipelineStage.REDACTED,
            f"inproc://lr-{opaque}-redacted",
        )
        self.redacted_to_encrypted = PipelineEndpoint(
            PipelineStage.REDACTED,
            PipelineStage.ENCRYPTED,
            f"inproc://lr-{opaque}-encrypted",
        )

    def all(self) -> tuple[PipelineEndpoint, ...]:
        return (
            self.ingress,
            self.raw_to_analyzed,
            self.analyzed_to_redacted,
            self.redacted_to_encrypted,
        )


class OwnedSocket:
    def __init__(self, socket: zmq.Socket[bytes]) -> None:
        self._socket = socket
        self._owner_thread = threading.get_ident()
        self._closed = False

    @property
    def raw(self) -> zmq.Socket[bytes]:
        self._assert_owner()
        return self._socket

    def send_multipart(self, frames: list[bytes]) -> None:
        self._assert_owner()
        cast(_MultipartSocket, self._socket).send_multipart(frames, flags=zmq.DONTWAIT, copy=True)

    def recv_multipart(self, *, nonblocking: bool = False) -> list[bytes]:
        self._assert_owner()
        flags = zmq.DONTWAIT if nonblocking else 0
        return cast(_MultipartSocket, self._socket).recv_multipart(flags=flags, copy=True)

    def close(self) -> None:
        self._assert_owner()
        if self._closed:
            return
        self._socket.setsockopt(zmq.LINGER, 0)
        self._socket.close(linger=0)
        self._closed = True

    def _assert_owner(self) -> None:
        if threading.get_ident() != self._owner_thread:
            raise PipelineOwnershipError("ZeroMQ socket used from a non-owner thread")


def make_pull_socket(
    context: zmq.Context[zmq.Socket[bytes]],
    endpoint: PipelineEndpoint,
    *,
    capacity: int,
    limits: PipelineLimits,
) -> OwnedSocket:
    socket = context.socket(zmq.PULL)
    _configure_socket(socket, capacity=capacity, limits=limits)
    socket.bind(endpoint.address)
    return OwnedSocket(socket)


def make_push_socket(
    context: zmq.Context[zmq.Socket[bytes]],
    endpoint: PipelineEndpoint,
    *,
    capacity: int,
    limits: PipelineLimits,
) -> OwnedSocket:
    socket = context.socket(zmq.PUSH)
    _configure_socket(socket, capacity=capacity, limits=limits)
    socket.setsockopt(zmq.IMMEDIATE, 1)
    socket.connect(endpoint.address)
    return OwnedSocket(socket)


def _configure_socket(socket: zmq.Socket[bytes], *, capacity: int, limits: PipelineLimits) -> None:
    socket.setsockopt(zmq.SNDHWM, capacity)
    socket.setsockopt(zmq.RCVHWM, capacity)
    socket.setsockopt(zmq.SNDTIMEO, limits.send_timeout_ms)
    socket.setsockopt(zmq.RCVTIMEO, limits.receive_timeout_ms)
    socket.setsockopt(zmq.LINGER, 0)
