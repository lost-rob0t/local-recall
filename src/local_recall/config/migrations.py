from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from .errors import ConfigurationMigrationError, UnsupportedSchemaVersion
from .models import CURRENT_SCHEMA_VERSION


def migrate_configuration(data: Mapping[str, Any]) -> dict[str, Any]:
    if "schema_version" not in data:
        raise ConfigurationMigrationError("configuration must declare schema_version")

    version = data["schema_version"]
    if type(version) is not int:
        raise ConfigurationMigrationError("schema_version must be an integer")
    if version > CURRENT_SCHEMA_VERSION:
        raise UnsupportedSchemaVersion(
            f"schema version {version} is newer than supported version {CURRENT_SCHEMA_VERSION}"
        )
    if version < 0:
        raise ConfigurationMigrationError("schema_version must not be negative")

    migrated = deepcopy(dict(data))
    while version < CURRENT_SCHEMA_VERSION:
        if version == 0:
            migrated = _migrate_v0_to_v1(migrated)
            version = 1
            continue
        raise ConfigurationMigrationError(f"no migration path from schema version {version}")
    return migrated


def _migrate_v0_to_v1(data: dict[str, Any]) -> dict[str, Any]:
    migrated = deepcopy(data)
    migrated["schema_version"] = 1

    if "privacy_mode" in migrated:
        if "profile" in migrated:
            raise ConfigurationMigrationError("v0 contains both privacy_mode and profile")
        migrated["profile"] = migrated.pop("privacy_mode")

    capture = dict(migrated.get("capture", {}))
    if "recording_enabled" in migrated:
        if "enabled" in capture:
            raise ConfigurationMigrationError(
                "v0 contains both recording_enabled and capture.enabled"
            )
        capture["enabled"] = migrated.pop("recording_enabled")
    if "interval_seconds" in migrated:
        if "cadence_seconds" in capture:
            raise ConfigurationMigrationError(
                "v0 contains both interval_seconds and capture.cadence_seconds"
            )
        capture["cadence_seconds"] = migrated.pop("interval_seconds")
    if capture:
        migrated["capture"] = capture
    return migrated
