"""Configuration management for eip-search CLI."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover
        import tomli as tomllib  # type: ignore[no-redef]

CONFIG_PATH = Path.home() / ".eip-search.toml"
DEFAULT_BASE_URL = "https://exploit-intel.com"
DEFAULT_PER_PAGE = 20
MAX_PER_PAGE = 100


@dataclass
class Config:
    """Application configuration loaded from ~/.eip-search.toml."""

    base_url: str = DEFAULT_BASE_URL
    api_key: str | None = None
    per_page: int = DEFAULT_PER_PAGE

    @classmethod
    def load(cls) -> Config:
        """Load config from TOML file, falling back to defaults."""
        if not CONFIG_PATH.exists():
            return cls()

        try:
            with open(CONFIG_PATH, "rb") as f:
                data = tomllib.load(f)
        except Exception:
            return cls()

        api_section = data.get("api", {})
        display_section = data.get("display", {})

        return cls(
            base_url=api_section.get("base_url", DEFAULT_BASE_URL).rstrip("/"),
            api_key=api_section.get("api_key"),
            per_page=min(display_section.get("per_page", DEFAULT_PER_PAGE), MAX_PER_PAGE),
        )


# Singleton loaded once at import
_config: Config | None = None


def get_config() -> Config:
    """Return the global config singleton."""
    global _config
    if _config is None:
        _config = Config.load()
    return _config
