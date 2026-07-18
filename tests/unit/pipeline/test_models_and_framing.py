from __future__ import annotations

import json
from uuid import uuid4

import pytest

from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.pipeline import (
    PipelineLimits,
    PipelineProtocolError,
    PipelineStage,
    RawStageItem,
    decode_item,
    encode_item,
)


def raw_item(payload: bytearray | None = None) -> RawStageItem:
    return RawStageItem(
        record_id=uuid4(),
        generation=CaptureGeneration(3),
        configuration_revision="config-v1",
        deadline_monotonic_ns=999_999_999_999_999,
        frames=(payload or bytearray(b"RAW-SECRET"),),
    )


def test_raw_item_repr_hides_content_and_destroy_zeroes_buffer() -> None:
    payload = bytearray(b"RAW-SECRET")
    item = raw_item(payload)

    assert "RAW-SECRET" not in repr(item)
    item.destroy()

    assert payload == bytearray(len(payload))


def test_framing_round_trip_reconstructs_exact_stage_type() -> None:
    source = raw_item()

    decoded = decode_item(
        encode_item(source, PipelineLimits()),
        expected_stage=PipelineStage.RAW,
        limits=PipelineLimits(),
    )

    assert isinstance(decoded, RawStageItem)
    assert decoded.record_id == source.record_id
    assert decoded.generation == source.generation
    assert tuple(bytes(frame) for frame in decoded.frames) == (b"RAW-SECRET",)


def test_framing_rejects_wrong_stage_without_echoing_content() -> None:
    source = raw_item()

    with pytest.raises(PipelineProtocolError) as captured:
        decode_item(
            encode_item(source, PipelineLimits()),
            expected_stage=PipelineStage.REDACTED,
            limits=PipelineLimits(),
        )

    assert str(source.record_id) in str(captured.value)
    assert "RAW-SECRET" not in str(captured.value)


def test_framing_rejects_unknown_fields_and_size_mismatch() -> None:
    parts = encode_item(raw_item(), PipelineLimits())
    header = json.loads(parts[0])
    header["unexpected"] = "field"
    parts[0] = json.dumps(header).encode()

    with pytest.raises(PipelineProtocolError, match="failed validation"):
        decode_item(parts, expected_stage=PipelineStage.RAW, limits=PipelineLimits())

    parts = encode_item(raw_item(), PipelineLimits())
    header = json.loads(parts[0])
    header["frame_sizes"] = [999]
    parts[0] = json.dumps(header).encode()

    with pytest.raises(PipelineProtocolError, match="size mismatch"):
        decode_item(parts, expected_stage=PipelineStage.RAW, limits=PipelineLimits())


def test_payload_limits_are_enforced_before_transport() -> None:
    limits = PipelineLimits(max_payload_bytes=4)

    with pytest.raises(PipelineProtocolError, match="configured limit"):
        encode_item(raw_item(bytearray(b"12345")), limits)


def test_framing_rejects_unknown_protocol_version() -> None:
    parts = encode_item(raw_item(), PipelineLimits())
    header = json.loads(parts[0])
    header["protocol_version"] = 99
    parts[0] = json.dumps(header).encode()

    with pytest.raises(PipelineProtocolError, match="unsupported protocol version"):
        decode_item(parts, expected_stage=PipelineStage.RAW, limits=PipelineLimits())


def test_framing_rejects_excess_multipart_frames() -> None:
    parts = encode_item(raw_item(), PipelineLimits())
    parts.extend([b"extra", b"extra"])

    with pytest.raises(PipelineProtocolError):
        decode_item(
            parts,
            expected_stage=PipelineStage.RAW,
            limits=PipelineLimits(max_frames=1),
        )
