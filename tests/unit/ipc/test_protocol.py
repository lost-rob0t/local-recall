from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from local_recall.cli_contract import CliCommand, CliRequest
from local_recall.ipc import SessionToken
from local_recall.ipc_protocol import (
    IpcCapability,
    IpcProtocolError,
    IpcRequestCodec,
    MAX_REQUEST_PAYLOAD_BYTES,
)

NOW = datetime(2026, 8, 22, 20, 0, tzinfo=UTC)


def _token(byte: int) -> SessionToken:
    return SessionToken(bytes([byte]) * SessionToken.BYTE_LENGTH)


def _expect_protocol_error(code: str, action: Callable[[], object]) -> None:
    try:
        action()
    except IpcProtocolError as exc:
        assert str(exc) == code
    else:
        raise AssertionError(f"expected {code}")


def test_query_round_trip_keeps_content_out_of_routing_frame() -> None:
    token = _token(1)
    codec = IpcRequestCodec(
        token=token,
        capabilities=frozenset({IpcCapability.QUERY}),
    )
    request = CliRequest.create(
        command=CliCommand.ASK,
        now=NOW,
        deadline=NOW + timedelta(seconds=2),
        query="What was I doing Saturday?",
        start=NOW - timedelta(hours=2),
        end=NOW - timedelta(hours=1),
    )

    frames = codec.encode(request)
    decoded = codec.decode(frames, now=NOW)

    assert len(frames) == 3
    assert request.query is not None
    assert request.query.encode() not in frames[0]
    assert decoded.request_id == request.request_id
    assert decoded.command is request.command
    assert decoded.priority is request.priority
    assert decoded.query == request.query
    assert decoded.start == request.start
    assert decoded.end == request.end


def test_wrong_session_token_is_rejected_before_payload_decode() -> None:
    server = IpcRequestCodec(
        token=_token(2),
        capabilities=frozenset({IpcCapability.CONTROL}),
    )
    client = IpcRequestCodec(
        token=_token(3),
        capabilities=frozenset({IpcCapability.CONTROL}),
    )
    request = CliRequest.create(
        command=CliCommand.STOP,
        now=NOW,
        deadline=NOW + timedelta(seconds=2),
    )
    frames = client.encode(request)
    hostile = (frames[0], frames[1], b"not-json-and-must-not-be-parsed")

    _expect_protocol_error("unauthorized", lambda: server.decode(hostile, now=NOW))


def test_query_capability_cannot_be_used_by_control_only_session() -> None:
    token = _token(4)
    client = IpcRequestCodec(
        token=token,
        capabilities=frozenset({IpcCapability.QUERY}),
    )
    server = IpcRequestCodec(
        token=token,
        capabilities=frozenset({IpcCapability.CONTROL}),
    )
    request = CliRequest.create(
        command=CliCommand.SEARCH,
        now=NOW,
        deadline=NOW + timedelta(seconds=2),
        query="synthetic query",
    )

    _expect_protocol_error(
        "capability-denied",
        lambda: server.decode(client.encode(request), now=NOW),
    )


def test_priority_spoof_is_rejected() -> None:
    token = _token(5)
    codec = IpcRequestCodec(
        token=token,
        capabilities=frozenset({IpcCapability.CONTROL}),
    )
    request = CliRequest.create(
        command=CliCommand.STATUS,
        now=NOW,
        deadline=NOW + timedelta(seconds=2),
    )
    frames = list(codec.encode(request))
    frames[0] = frames[0].replace(b'"priority":"control"', b'"priority":"urgent-control"')

    _expect_protocol_error("priority-mismatch", lambda: codec.decode(tuple(frames), now=NOW))


def test_oversized_payload_is_rejected_without_decoding() -> None:
    token = _token(6)
    codec = IpcRequestCodec(
        token=token,
        capabilities=frozenset({IpcCapability.CONTROL}),
    )
    request = CliRequest.create(
        command=CliCommand.STATUS,
        now=NOW,
        deadline=NOW + timedelta(seconds=2),
    )
    frames = list(codec.encode(request))
    frames[2] = b"x" * (MAX_REQUEST_PAYLOAD_BYTES + 1)

    _expect_protocol_error("payload-too-large", lambda: codec.decode(tuple(frames), now=NOW))
