from __future__ import annotations


class ConfigurationError(ValueError):
    """Base class for configuration failures safe to report without input values."""


class ConfigurationLoadError(ConfigurationError):
    """Configuration could not be parsed or validated."""


class UnsupportedSchemaVersion(ConfigurationError):
    """Configuration schema is newer than this runtime supports."""


class ConfigurationMigrationError(ConfigurationError):
    """Configuration could not be migrated without ambiguity."""
