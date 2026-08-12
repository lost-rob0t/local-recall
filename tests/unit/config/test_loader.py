from __future__ import annotations

from pathlib import Path

import pytest

from local_recall.config import (
    ConfigurationLoadError,
    ConfigurationMigrationError,
    UnsupportedSchemaVersion,
    inspect_effective_configuration,
    load_configuration_file,
    load_configuration_mapping,
    migrate_configuration,
)


def valid_mapping() -> dict[str, object]:
    return {
        "schema_version": 1,
        "profile": "local-only",
        "capture": {"enabled": False},
    }


def test_loader_requires_schema_version() -> None:
    with pytest.raises(ConfigurationMigrationError, match="schema_version"):
        load_configuration_mapping({})


def test_loader_rejects_future_schema() -> None:
    with pytest.raises(UnsupportedSchemaVersion, match="newer"):
        load_configuration_mapping({"schema_version": 99})


def test_v0_migration_is_deterministic() -> None:
    migrated = migrate_configuration(
        {
            "schema_version": 0,
            "privacy_mode": "local-only",
            "recording_enabled": False,
            "interval_seconds": 12,
        }
    )

    assert migrated == {
        "schema_version": 1,
        "profile": "local-only",
        "capture": {"enabled": False, "cadence_seconds": 12},
    }


def test_v0_migration_rejects_ambiguous_fields() -> None:
    with pytest.raises(ConfigurationMigrationError, match="both privacy_mode and profile"):
        migrate_configuration(
            {
                "schema_version": 0,
                "privacy_mode": "local-only",
                "profile": "privacy-strict",
            }
        )


def test_non_secret_environment_overrides_are_applied() -> None:
    loaded = load_configuration_mapping(
        valid_mapping(),
        environ={
            "LOCAL_RECALL_PROFILE": "local-first",
            "LOCAL_RECALL_CAPTURE_CADENCE_SECONDS": "30",
            "LOCAL_RECALL_MODELS_REMOTE_ENABLED": "false",
        },
    )

    assert loaded.configuration.profile.value == "local-first"
    assert loaded.configuration.capture.cadence_seconds == 30
    assert not loaded.configuration.models.remote_enabled


def test_unknown_environment_override_fails_closed() -> None:
    forbidden_variable = "LOCAL_RECALL_" + "API" + "_KEY"
    with pytest.raises(ConfigurationLoadError, match="unsupported"):
        load_configuration_mapping(
            valid_mapping(),
            environ={forbidden_variable: "not-accepted"},
        )


def test_environment_override_errors_omit_values() -> None:
    marker = "VALUE-MUST-NOT-APPEAR"
    with pytest.raises(ConfigurationLoadError) as captured:
        load_configuration_mapping(
            valid_mapping(),
            environ={"LOCAL_RECALL_CAPTURE_ENABLED": marker},
        )

    assert marker not in str(captured.value)


def test_validation_errors_omit_input_values() -> None:
    marker = "VALUE-MUST-NOT-APPEAR"
    with pytest.raises(ConfigurationLoadError) as captured:
        load_configuration_mapping(
            {
                "schema_version": 1,
                "profile": marker,
            }
        )

    assert marker not in str(captured.value)


def test_effective_configuration_hides_key_references() -> None:
    loaded = load_configuration_mapping(
        {
            "schema_version": 1,
            "profile": "local-only",
            "capture": {"enabled": True},
            "metadata": {"enabled_sources": ["xorg-generic"]},
            "encryption": {
                "provider_id": "keyring",
                "key_reference": {
                    "provider_id": "keyring",
                    "reference": "actual-reference-name",
                },
            },
            "storage": {
                "backend_id": "sqlite-blobs",
                "root_directory": "/tmp/local-recall-test",
            },
        }
    )

    rendered = inspect_effective_configuration(loaded.configuration)

    assert rendered["encryption"]["key_reference"] == {
        "provider_id": "keyring",
        "reference": "<configured>",
    }
    assert "actual-reference-name" not in str(rendered)


def test_revision_is_stable_for_equivalent_configuration() -> None:
    first = load_configuration_mapping(valid_mapping())
    second = load_configuration_mapping(
        {
            "profile": "local-only",
            "capture": {"enabled": False},
            "schema_version": 1,
        }
    )

    assert first.revision == second.revision


def test_toml_loader_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "config.toml"
    target.write_text('schema_version = 1\nprofile = "privacy-strict"\n', encoding="utf-8")
    link = tmp_path / "link.toml"
    link.symlink_to(target)

    with pytest.raises(ConfigurationLoadError, match="symbolic link"):
        load_configuration_file(link, environ={})


def test_toml_loader_reads_versioned_config(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text('schema_version = 1\nprofile = "local-only"\n', encoding="utf-8")

    loaded = load_configuration_file(path, environ={})

    assert loaded.configuration.profile.value == "local-only"
    assert loaded.source == str(path)


def test_loader_accepts_independent_window_title_setting() -> None:
    loaded = load_configuration_mapping(
        {
            "schema_version": 1,
            "profile": "local-only",
            "metadata": {
                "enabled_sources": ["xorg-generic"],
                "window_titles_enabled": True,
            },
        }
    )

    assert loaded.configuration.metadata.window_titles_enabled
