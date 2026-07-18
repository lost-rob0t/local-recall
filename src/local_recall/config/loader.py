from __future__ import annotations

import hashlib
import json
import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .environment import apply_environment_overrides
from .errors import ConfigurationError, ConfigurationLoadError
from .migrations import migrate_configuration
from .models import LocalRecallConfig

_MAX_CONFIG_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class LoadedConfiguration:
    configuration: LocalRecallConfig
    revision: str
    source: str


def load_configuration_mapping(
    data: Mapping[str, Any],
    *,
    environ: Mapping[str, str] | None = None,
    source: str = "mapping",
) -> LoadedConfiguration:
    try:
        migrated = migrate_configuration(data)
        overridden = apply_environment_overrides(migrated, environ or {})
        configuration = LocalRecallConfig.model_validate(overridden)
    except ConfigurationError:
        raise
    except ValidationError as exc:
        raise ConfigurationLoadError(_format_validation_error(exc)) from exc
    return LoadedConfiguration(
        configuration=configuration,
        revision=configuration_revision(configuration),
        source=source,
    )


def load_configuration_file(
    path: Path,
    *,
    environ: Mapping[str, str] | None = None,
) -> LoadedConfiguration:
    try:
        if path.is_symlink():
            raise ConfigurationLoadError("configuration file must not be a symbolic link")
        stat_result = path.stat()
        if not path.is_file():
            raise ConfigurationLoadError("configuration path must be a regular file")
        if stat_result.st_size > _MAX_CONFIG_BYTES:
            raise ConfigurationLoadError("configuration file exceeds the size limit")
        raw = path.read_bytes()
        parsed = tomllib.loads(raw.decode("utf-8"))
    except ConfigurationError:
        raise
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationLoadError("configuration file could not be parsed") from exc
    return load_configuration_mapping(
        parsed,
        environ=environ if environ is not None else os.environ,
        source=str(path),
    )


def configuration_revision(configuration: LocalRecallConfig) -> str:
    canonical = json.dumps(
        configuration.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _format_validation_error(error: ValidationError) -> str:
    findings: list[str] = []
    for item in error.errors(include_input=False, include_url=False):
        location = ".".join(str(segment) for segment in item["loc"])
        findings.append(f"{location}: {item['msg']}")
    return "invalid configuration: " + "; ".join(findings)
