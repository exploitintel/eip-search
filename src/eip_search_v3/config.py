"""Configuration with explicit environment and CLI precedence."""

from __future__ import annotations

import math
import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .errors import InputError

DEFAULT_BASE_URL = "https://exploit-intel.com"
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 1024 * 1024 * 1024


def _config_path(env: Mapping[str, str]) -> Path:
    configured = env.get("EIP_SEARCH_CONFIG")
    if configured:
        return Path(configured).expanduser()
    root = Path(env.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return root / "eip-search" / "config.toml"


def _read_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise InputError(f"Cannot read configuration {path}: {exc}") from None
    api = data.get("api", {})
    if not isinstance(api, dict):
        raise InputError(f"Configuration {path}: [api] must be a table")
    return api


def _finite_float(name: str, value: object, *, low: float, high: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        raise InputError(f"{name} must be a number") from None
    if not math.isfinite(parsed) or not low <= parsed <= high:
        raise InputError(f"{name} must be between {low:g} and {high:g}")
    return parsed


def _bounded_int(name: str, value: object, *, low: int, high: int) -> int:
    if isinstance(value, bool):
        raise InputError(f"{name} must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise InputError(f"{name} must be an integer") from None
    if not low <= parsed <= high:
        raise InputError(f"{name} must be between {low} and {high}")
    return parsed


def normalize_base_url(value: object) -> str:
    raw = str(value).strip()
    if any(ord(char) < 32 or ord(char) == 127 for char in raw) or "\\" in raw:
        raise InputError("API base URL contains invalid characters")
    try:
        parsed = urlsplit(raw)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise InputError(f"Invalid API base URL: {exc}") from None
    if parsed.scheme not in {"http", "https"} or not hostname:
        raise InputError("API base URL must be an absolute HTTP(S) URL")
    if parsed.scheme == "http":
        local_name = hostname.casefold() == "localhost" or hostname.casefold().endswith(
            ".localhost"
        )
        try:
            local_address = ip_address(hostname).is_loopback
        except ValueError:
            local_address = False
        if not local_name and not local_address:
            raise InputError("Remote API base URLs must use HTTPS")
    if port is not None and not 1 <= port <= 65_535:
        raise InputError("API base URL port must be between 1 and 65535")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise InputError("API base URL must not contain credentials, a query, or a fragment")
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


@dataclass(frozen=True, slots=True)
class Settings:
    base_url: str
    timeout_seconds: float
    max_download_bytes: int

    @classmethod
    def load(
        cls,
        *,
        base_url: str | None = None,
        timeout_seconds: float | None = None,
        env: Mapping[str, str] | None = None,
    ) -> Settings:
        source = os.environ if env is None else env
        file_values = _read_config(_config_path(source))
        if base_url is not None:
            resolved_url: object = base_url
        elif "EIP_API_BASE_URL" in source:
            resolved_url = source["EIP_API_BASE_URL"]
        elif "base_url" in file_values:
            resolved_url = file_values["base_url"]
        else:
            resolved_url = DEFAULT_BASE_URL
        resolved_timeout: object = (
            timeout_seconds
            if timeout_seconds is not None
            else source.get(
                "EIP_SEARCH_TIMEOUT_SECONDS",
                file_values.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS),
            )
        )
        resolved_download: object = source.get(
            "EIP_SEARCH_MAX_DOWNLOAD_BYTES",
            file_values.get("max_download_bytes", DEFAULT_MAX_DOWNLOAD_BYTES),
        )
        return cls(
            base_url=normalize_base_url(resolved_url),
            timeout_seconds=_finite_float("timeout_seconds", resolved_timeout, low=1.0, high=900.0),
            max_download_bytes=_bounded_int(
                "max_download_bytes",
                resolved_download,
                low=1024 * 1024,
                high=MAX_DOWNLOAD_BYTES,
            ),
        )
