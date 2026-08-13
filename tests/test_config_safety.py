from __future__ import annotations

from pathlib import Path

import pytest

from eip_search_v3.config import Settings, normalize_base_url
from eip_search_v3.errors import InputError
from eip_search_v3.safety import clean, safe_filename, safe_language


def test_configuration_precedence_and_file(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        '[api]\nbase_url = "https://file.example/api/"\n'
        "timeout_seconds = 12\nmax_download_bytes = 2097152\n"
    )
    settings = Settings.load(env={"EIP_SEARCH_CONFIG": str(config)})
    assert settings.base_url == "https://file.example/api"
    assert settings.timeout_seconds == 12
    assert settings.max_download_bytes == 2 * 1024 * 1024

    settings = Settings.load(
        base_url="https://cli.example/",
        timeout_seconds=20,
        env={
            "EIP_SEARCH_CONFIG": str(config),
            "EIP_API_BASE_URL": "https://env.example",
            "EIP_SEARCH_TIMEOUT_SECONDS": "15",
        },
    )
    assert settings.base_url == "https://cli.example"
    assert settings.timeout_seconds == 20


@pytest.mark.parametrize(
    "value",
    [
        "example.com",
        "ftp://example.com",
        "https://u:p@example.com",
        "https://x/?q=1",
        "https://example.com:bad",
        "https://[::1",
        "https://exa\\mple.com",
        "https://exa\x00mple.com",
        "http://example.com",
        "http://192.0.2.10:8080",
    ],
)
def test_invalid_base_urls(value: str) -> None:
    with pytest.raises(InputError):
        normalize_base_url(value)


def test_explicit_empty_base_url_does_not_silently_use_a_default() -> None:
    with pytest.raises(InputError, match="absolute HTTP"):
        Settings.load(base_url="", env={})
    with pytest.raises(InputError, match="absolute HTTP"):
        Settings.load(env={"EIP_API_BASE_URL": ""})


@pytest.mark.parametrize(
    "value, expected",
    [
        ("http://localhost:8000/", "http://localhost:8000"),
        ("http://api.localhost/v1/", "http://api.localhost/v1"),
        ("http://127.0.0.1:13002/", "http://127.0.0.1:13002"),
        ("http://[::1]:13002/", "http://[::1]:13002"),
    ],
)
def test_loopback_http_base_urls_are_allowed(value: str, expected: str) -> None:
    assert normalize_base_url(value) == expected


def test_invalid_configuration_values(tmp_path: Path) -> None:
    config = tmp_path / "bad.toml"
    config.write_text("[api\n")
    with pytest.raises(InputError, match="Cannot read configuration"):
        Settings.load(env={"EIP_SEARCH_CONFIG": str(config)})

    config.write_text("api = 1\n")
    with pytest.raises(InputError, match="must be a table"):
        Settings.load(env={"EIP_SEARCH_CONFIG": str(config)})

    with pytest.raises(InputError, match="timeout_seconds"):
        Settings.load(env={"EIP_SEARCH_TIMEOUT_SECONDS": "nan"})
    with pytest.raises(InputError, match="max_download_bytes"):
        Settings.load(env={"EIP_SEARCH_MAX_DOWNLOAD_BYTES": "1"})


def test_hostile_terminal_text_and_filenames_are_contained() -> None:
    hostile = "[bold]owned[/bold]\x1b[31mRED\x1b[0m\x1b]0;title\x07\x00"
    assert clean(hostile) == "[bold]owned[/bold]RED"
    assert clean("a\nb\tc", multiline=False) == "a b c"
    assert clean("a\r\nb\rc", multiline=True) == "a\nb\nc"
    assert clean("a\u2028b\u2029c", multiline=True) == "abc"
    assert clean("abcdef", limit=4) == "abc…"
    assert safe_filename("../../evil name.zip", "fallback.zip") == "evil_name.zip"
    assert safe_filename("...", "fallback.zip") == "fallback.zip"
    assert safe_filename("-danger.zip", "fallback.zip") == "_-danger.zip"
    assert safe_filename("CON.txt", "fallback.zip") == "_CON.txt"
    assert safe_language("Python") == "python"
    assert safe_language("unknown\x1b[2J") == "text"
