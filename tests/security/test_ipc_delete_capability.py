from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from local_recall import ipc, ipc_protocol
from local_recall.cli_contract import CliCommand, CliRequest

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)


def _token(byte: int) -> ipc.SessionToken:
    return ipc.SessionToken(bytes([byte]) * ipc.SessionToken.BYTE_LENGTH)


def _delete_request() -> CliRequest:
    return CliRequest.create(
        command=CliCommand.DELETE_RECORDS,
        now=NOW,
        deadline=NOW + timedelta(seconds=2),
        record_ids=("c0ffee00-0000-4000-8000-000000000001",),
    )


def _expect_denied(action: object) -> None:
    try:
        action()
    except ipc_protocol.IpcProtocolError as exc:
        assert str(exc) == "capability-denied"
    else:
        raise AssertionError("delete request was accepted without the delete capability")


def test_delete_records_requires_the_delete_capability() -> None:
    client = ipc_protocol.IpcRequestCodec(
        token=_token(1),
        capabilities=frozenset(
            {
                ipc_protocol.IpcCapability.CONTROL,
                ipc_protocol.IpcCapability.QUERY,
                ipc_protocol.IpcCapability.DIAGNOSTIC,
                ipc_protocol.IpcCapability.EXPORT,
            }
        ),
    )
    _expect_denied(lambda: client.encode(_delete_request()))


def test_delete_records_is_authorized_with_delete_capability() -> None:
    token = _token(2)
    client = ipc_protocol.IpcRequestCodec(
        token=token,
        capabilities=frozenset({ipc_protocol.IpcCapability.DELETE}),
    )
    frames = client.encode(_delete_request())
    server = ipc_protocol.IpcRequestCodec(
        token=token,
        capabilities=frozenset({ipc_protocol.IpcCapability.DELETE}),
    )
    decoded = server.decode(frames, now=NOW)
    assert decoded.command is CliCommand.DELETE_RECORDS
    assert decoded.record_ids == ("c0ffee00-0000-4000-8000-000000000001",)


def test_delete_records_capability_denied_is_explicit_not_generic() -> None:
    client = ipc_protocol.IpcRequestCodec(
        token=_token(3),
        capabilities=frozenset({ipc_protocol.IpcCapability.QUERY}),
    )
    _expect_denied(lambda: client.encode(_delete_request()))


def test_wrong_token_delete_is_unauthorized_even_with_capability() -> None:
    client = ipc_protocol.IpcRequestCodec(
        token=_token(4),
        capabilities=frozenset({ipc_protocol.IpcCapability.DELETE}),
    )
    server = ipc_protocol.IpcRequestCodec(
        token=_token(5),
        capabilities=frozenset({ipc_protocol.IpcCapability.DELETE}),
    )
    frames = client.encode(_delete_request())
    with pytest.raises(ipc_protocol.IpcProtocolError) as raised:
        server.decode(frames, now=NOW)
    assert str(raised.value) == "unauthorized"


def test_delete_capability_is_required_on_the_server_side_too() -> None:
    client = ipc_protocol.IpcRequestCodec(
        token=_token(6),
        capabilities=frozenset({ipc_protocol.IpcCapability.DELETE}),
    )
    server = ipc_protocol.IpcRequestCodec(
        token=_token(6),
        capabilities=frozenset({ipc_protocol.IpcCapability.QUERY}),
    )
    frames = client.encode(_delete_request())
    _expect_denied(lambda: server.decode(frames, now=NOW))
