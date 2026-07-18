from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from local_recall.config import ConfigurationManager


class FrozenClock:
    def now(self) -> datetime:
        return datetime(2026, 7, 18, tzinfo=UTC)

    def monotonic_ns(self) -> int:
        return 1


def enabled_mapping() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "profile": "local-only",
        "capture": {"enabled": True},
        "metadata": {"enabled_sources": ["generic-xorg"]},
        "rules": {
            "default_effect": "deny",
            "rules": [{"effect": "allow", "application": "synthetic-app"}],
        },
        "encryption": {
            "provider_id": "keyring",
            "key_reference": {"provider_id": "keyring", "reference": "record-key"},
        },
        "storage": {
            "backend_id": "sqlite-blobs",
            "root_directory": "/tmp/local-recall-test",
        },
    }


def test_manager_starts_capture_disabled() -> None:
    manager = ConfigurationManager(clock=FrozenClock())

    assert not manager.snapshot().configuration.capture_permitted


def test_valid_reload_is_atomic() -> None:
    manager = ConfigurationManager(clock=FrozenClock())
    before = manager.snapshot()

    outcome = manager.reload_mapping(enabled_mapping(), source="test")

    assert outcome.accepted
    assert outcome.snapshot is manager.snapshot()
    assert outcome.snapshot.configuration.capture_permitted
    assert outcome.snapshot.revision != before.revision


def test_invalid_reload_replaces_active_configuration_with_safe_default() -> None:
    manager = ConfigurationManager(clock=FrozenClock())
    assert manager.reload_mapping(enabled_mapping()).accepted
    assert manager.snapshot().configuration.capture_permitted

    outcome = manager.reload_mapping(
        {
            "schema_version": 1,
            "profile": "local-only",
            "capture": {"enabled": True},
        }
    )

    assert not outcome.accepted
    assert not outcome.snapshot.configuration.capture_permitted
    assert not manager.snapshot().configuration.capture_permitted
    assert outcome.snapshot.source == "reload-rejected"
    assert outcome.error_code == "ConfigurationLoadError"


def test_failed_reload_never_exposes_partial_candidate() -> None:
    manager = ConfigurationManager(clock=FrozenClock())
    candidate = enabled_mapping()
    candidate["capture"] = {"enabled": True, "cadence_seconds": 99}
    candidate["storage"] = {"backend_id": "sqlite-blobs"}

    outcome = manager.reload_mapping(candidate)
    snapshot = manager.snapshot()

    assert not outcome.accepted
    assert snapshot.configuration.capture.cadence_seconds == 15
    assert snapshot.configuration.storage.backend_id is None
    assert not snapshot.configuration.capture.enabled
