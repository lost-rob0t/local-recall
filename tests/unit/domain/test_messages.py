from datetime import UTC, datetime
from uuid import uuid4

import pytest

from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.messages import EventEnvelope, MessageEnvelope, MessageHeader
from local_recall.domain.privacy import PrivacyClass


def header() -> MessageHeader:
    return MessageHeader(
        protocol_version=1,
        message_type="synthetic.request",
        message_id=uuid4(),
        correlation_id=None,
        generation=CaptureGeneration(1),
        configuration_revision="config-v1",
        deadline_monotonic_ns=100,
        privacy_class=PrivacyClass.OPERATIONAL_METADATA,
        declared_payload_bytes=0,
    )


def test_message_header_requires_positive_protocol_version() -> None:
    with pytest.raises(ValueError, match="protocol version"):
        MessageHeader(
            protocol_version=0,
            message_type="synthetic.request",
            message_id=uuid4(),
            correlation_id=None,
            generation=None,
            configuration_revision="config-v1",
            deadline_monotonic_ns=100,
            privacy_class=PrivacyClass.OPERATIONAL_METADATA,
            declared_payload_bytes=0,
        )


def test_generic_message_and_event_envelopes_are_immutable() -> None:
    message = MessageEnvelope(header=header(), payload=("synthetic",))
    event = EventEnvelope(
        event_id=uuid4(),
        event_type="synthetic.event",
        occurred_at=datetime.now(UTC),
        payload=message,
    )

    with pytest.raises(AttributeError):
        message.payload = ()  # type: ignore[misc]

    assert event.payload is message
