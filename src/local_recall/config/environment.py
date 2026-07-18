from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any, cast

from .errors import ConfigurationLoadError

_ENVIRONMENT_OVERRIDES: dict[str, tuple[str, ...]] = {
    "LOCAL_RECALL_PROFILE": ("profile",),
    "LOCAL_RECALL_CAPTURE_ENABLED": ("capture", "enabled"),
    "LOCAL_RECALL_CAPTURE_CADENCE_SECONDS": ("capture", "cadence_seconds"),
    "LOCAL_RECALL_CAPTURE_SCREENSHOTS_ENABLED": ("capture", "screenshots_enabled"),
    "LOCAL_RECALL_RETENTION_MAX_AGE_DAYS": ("retention", "max_age_days"),
    "LOCAL_RECALL_RETENTION_MAX_BYTES": ("retention", "max_bytes"),
    "LOCAL_RECALL_MODELS_GENERATION_PROVIDER": ("models", "generation_provider"),
    "LOCAL_RECALL_MODELS_EMBEDDING_PROVIDER": ("models", "embedding_provider"),
    "LOCAL_RECALL_MODELS_REMOTE_ENABLED": ("models", "remote_enabled"),
    "LOCAL_RECALL_ENCRYPTION_PROVIDER": ("encryption", "provider_id"),
    "LOCAL_RECALL_STORAGE_BACKEND": ("storage", "backend_id"),
}
_IGNORED_ENVIRONMENT_VARIABLES = {"LOCAL_RECALL_CONFIG"}


def apply_environment_overrides(
    data: Mapping[str, Any], environ: Mapping[str, str]
) -> dict[str, Any]:
    unknown = sorted(
        key
        for key in environ
        if key.startswith("LOCAL_RECALL_")
        and key not in _ENVIRONMENT_OVERRIDES
        and key not in _IGNORED_ENVIRONMENT_VARIABLES
    )
    if unknown:
        raise ConfigurationLoadError(f"unsupported Local Recall environment override: {unknown[0]}")

    result: dict[str, Any] = {key: deepcopy(value) for key, value in data.items()}
    for variable, path in _ENVIRONMENT_OVERRIDES.items():
        if variable not in environ:
            continue
        _set_nested(result, path, _parse_value(variable, environ[variable]))
    return result


def _set_nested(target: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    cursor: dict[str, Any] = target
    for segment in path[:-1]:
        child = cursor.get(segment)
        if child is None:
            nested: dict[str, Any] = {}
            cursor[segment] = nested
            cursor = nested
            continue
        if not isinstance(child, dict):
            raise ConfigurationLoadError(
                f"environment override conflicts with non-object field: {segment}"
            )
        cursor = cast(dict[str, Any], child)
    cursor[path[-1]] = value


def _parse_value(variable: str, value: str) -> str | bool | int | float:
    if variable.endswith("_ENABLED"):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
        raise ConfigurationLoadError(f"{variable} must be a boolean")
    if variable in {
        "LOCAL_RECALL_RETENTION_MAX_AGE_DAYS",
        "LOCAL_RECALL_RETENTION_MAX_BYTES",
    }:
        try:
            return int(value)
        except ValueError as exc:
            raise ConfigurationLoadError(f"{variable} must be an integer") from exc
    if variable == "LOCAL_RECALL_CAPTURE_CADENCE_SECONDS":
        try:
            return float(value)
        except ValueError as exc:
            raise ConfigurationLoadError(f"{variable} must be numeric") from exc
    return value
