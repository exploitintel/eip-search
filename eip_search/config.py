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
DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
DEFAULT_VISION_MODEL = "qwen3-vl:235b-instruct-cloud"
DEFAULT_CODE_MODEL = "kimi-k2:1t-cloud"
DEFAULT_DB_URL = "https://repo.exploit-intel.com/data/eip.db.gz"


@dataclass
class Config:
    """Application configuration loaded from ~/.eip-search.toml."""

    base_url: str = DEFAULT_BASE_URL
    api_key: str | None = None
    per_page: int = DEFAULT_PER_PAGE
    ollama_url: str = DEFAULT_OLLAMA_URL
    vision_model: str = DEFAULT_VISION_MODEL
    code_model: str = DEFAULT_CODE_MODEL
    db_path: str | None = None
    db_url: str | None = None
    exploits_dir: str | None = None

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
        gen_section = data.get("generate", {})
        offline_section = data.get("offline", {})

        return cls(
            base_url=api_section.get("base_url", DEFAULT_BASE_URL).rstrip("/"),
            api_key=api_section.get("api_key"),
            per_page=min(display_section.get("per_page", DEFAULT_PER_PAGE), MAX_PER_PAGE),
            ollama_url=gen_section.get("ollama_url", DEFAULT_OLLAMA_URL).rstrip("/"),
            vision_model=gen_section.get("vision_model", DEFAULT_VISION_MODEL),
            code_model=gen_section.get("code_model", DEFAULT_CODE_MODEL),
            db_path=offline_section.get("db_path"),
            db_url=offline_section.get("db_url"),
            exploits_dir=offline_section.get("exploits_dir"),
        )


# Singleton loaded once at import
_config: Config | None = None


def get_config() -> Config:
    """Return the global config singleton."""
    global _config
    if _config is None:
        _config = Config.load()
    return _config
