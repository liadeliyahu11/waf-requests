"""Process-wide configuration for the module-level API functions."""
from __future__ import annotations

from dataclasses import dataclass

from .engine import WAFSession


@dataclass(frozen=True)
class Config:
    profile: str = "auto"
    verbose: bool = False
    max_attempts: int = 6
    ladder: "tuple[str, ...] | None" = None
    retry_mutating: bool = True
    body_limit: "int | None" = None
    strict_fidelity: bool = False


_config = Config()

_CONFIG_FIELDS = tuple(Config.__dataclass_fields__)


def configure(**overrides) -> None:
    """Update module-level defaults; affects later top-level calls only."""
    global _config
    unknown = set(overrides) - set(_CONFIG_FIELDS)
    if unknown:
        raise TypeError(f"unknown configure options: {sorted(unknown)}")
    current = {field: getattr(_config, field) for field in _CONFIG_FIELDS}
    current.update(overrides)
    _config = Config(**current)


def get_config() -> Config:
    return _config


def default_session() -> WAFSession:
    config = _config
    return WAFSession(
        profile=config.profile,
        verbose=config.verbose,
        max_attempts=config.max_attempts,
        ladder=config.ladder,
        retry_mutating=config.retry_mutating,
        body_limit=config.body_limit,
        strict_fidelity=config.strict_fidelity,
    )
