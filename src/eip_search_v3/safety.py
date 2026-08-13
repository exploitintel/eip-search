"""Terminal and filesystem containment for hostile corpus values."""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path

_ANSI_CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_ANSI_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")
_WINDOWS_RESERVED = re.compile(r"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", re.I)


def clean(value: object, *, limit: int = 2_000, multiline: bool = False) -> str:
    text = "" if value is None else str(value)
    text = _ANSI_OSC.sub("", _ANSI_CSI.sub("", text))
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    kept: list[str] = []
    for char in text:
        if char == "\n":
            kept.append("\n" if multiline else " ")
        elif char == "\t":
            kept.append("\t" if multiline else " ")
        elif unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"}:
            continue
        else:
            kept.append(char)
    normalized = "".join(kept)
    if not multiline:
        normalized = " ".join(normalized.split())
    if len(normalized) <= limit:
        return normalized
    return normalized[: max(0, limit - 1)].rstrip() + "…"


def safe_filename(value: object, fallback: str) -> str:
    candidate = Path(str(value)).name.strip().replace("\x00", "")
    candidate = _SAFE_FILENAME.sub("_", candidate).strip("._")
    if candidate.startswith("-") or _WINDOWS_RESERVED.match(candidate):
        candidate = f"_{candidate}"
    return candidate[:180] or fallback


def safe_language(value: object) -> str:
    key = clean(value, limit=40).lower()
    aliases = {
        "c++": "cpp",
        "c#": "csharp",
        "golang": "go",
        "javascript": "javascript",
        "typescript": "typescript",
        "python": "python",
        "ruby": "ruby",
        "go": "go",
        "rust": "rust",
        "c": "c",
        "cpp": "cpp",
        "csharp": "csharp",
        "java": "java",
        "php": "php",
        "powershell": "powershell",
        "shell": "bash",
        "bash": "bash",
        "html": "html",
        "xml": "xml",
        "yaml": "yaml",
        "json": "json",
        "markdown": "markdown",
    }
    return aliases.get(key, "text")
