#!/usr/bin/env python3
"""Bump project version in-place.

Updates:
- pyproject.toml
- eip_search/__init__.py

Usage:
    python scripts/bump_version.py 0.2.0
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def _replace_once(path: Path, pattern: str, replacement: str) -> None:
    text = path.read_text(encoding="utf-8")
    new_text, n = re.subn(pattern, replacement, text, flags=re.M)
    if n != 1:
        raise SystemExit(f"Expected 1 replacement in {path}, got {n}")
    path.write_text(new_text, encoding="utf-8")


def main() -> None:
    if len(sys.argv) != 2 or not SEMVER_RE.match(sys.argv[1]):
        raise SystemExit("Usage: python scripts/bump_version.py X.Y.Z")

    version = sys.argv[1]
    root = Path(__file__).resolve().parents[1]

    _replace_once(
        root / "pyproject.toml",
        r'^version = ".*"$',
        f'version = "{version}"',
    )
    _replace_once(
        root / "eip_search/__init__.py",
        r'^__version__ = ".*"$',
        f'__version__ = "{version}"',
    )

    print(f"Bumped version to {version}")


if __name__ == "__main__":
    main()
