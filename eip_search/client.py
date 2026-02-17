"""HTTP client for the EIP API."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import httpx
from rich.console import Console

from eip_search.config import get_config
from eip_search.models import (
    ExploitFile,
    SearchResult,
    Stats,
    VulnDetail,
)

console = Console(stderr=True)

# Reusable client headers
USER_AGENT = "eip-search/0.1.0"
TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0)


class APIError(Exception):
    """Raised when the API returns a non-2xx status."""

    def __init__(self, status_code: int, message: str, retry_after: int | None = None):
        self.status_code = status_code
        self.message = message
        self.retry_after = retry_after
        super().__init__(message)


def _build_headers() -> dict[str, str]:
    cfg = get_config()
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if cfg.api_key:
        headers["X-API-Key"] = cfg.api_key
    return headers


def _handle_response(resp: httpx.Response) -> dict[str, Any]:
    """Check response status and return parsed JSON."""
    if resp.status_code == 404:
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        raise APIError(404, data.get("message", "Not found"))
    if resp.status_code == 429:
        retry_after = int(resp.headers.get("Retry-After", "60"))
        raise APIError(429, f"Rate limited. Try again in {retry_after}s.", retry_after=retry_after)
    if resp.status_code >= 400:
        raise APIError(resp.status_code, f"API error: HTTP {resp.status_code}")
    return resp.json()


def _api_url(path: str) -> str:
    cfg = get_config()
    return f"{cfg.base_url}{path}"


# ---------------------------------------------------------------------------
# Public API methods
# ---------------------------------------------------------------------------

def search_vulns(params: dict[str, Any]) -> SearchResult:
    """Search vulnerabilities with filters.

    ``params`` maps directly to the /api/v1/vulns query parameters.
    """
    clean = {k: v for k, v in params.items() if v is not None}
    with httpx.Client(timeout=TIMEOUT, headers=_build_headers(), follow_redirects=True) as client:
        resp = client.get(_api_url("/api/v1/vulns"), params=clean)
    return SearchResult.from_dict(_handle_response(resp))


def get_vuln_detail(vuln_id: str) -> VulnDetail:
    """Get full vulnerability detail by CVE-ID or EIP-ID."""
    with httpx.Client(timeout=TIMEOUT, headers=_build_headers(), follow_redirects=True) as client:
        resp = client.get(_api_url(f"/api/v1/vulns/{vuln_id}"))
    return VulnDetail.from_dict(_handle_response(resp))


def list_exploit_files(exploit_id: int) -> list[ExploitFile]:
    """List files in an exploit archive."""
    with httpx.Client(timeout=TIMEOUT, headers=_build_headers(), follow_redirects=True) as client:
        resp = client.get(_api_url(f"/api/v1/exploits/{exploit_id}/files"))
    data = _handle_response(resp)
    return [ExploitFile.from_dict(f) for f in data.get("files", [])]


def get_exploit_code(exploit_id: int, file_path: str) -> str:
    """Get source code content for a specific file in an exploit."""
    with httpx.Client(timeout=TIMEOUT, headers=_build_headers(), follow_redirects=True) as client:
        resp = client.get(
            _api_url(f"/api/v1/exploits/{exploit_id}/code"),
            params={"file": file_path},
        )
    data = _handle_response(resp)
    return data.get("content", "")


MAX_DOWNLOAD_SIZE = 50 * 1024 * 1024  # 50 MB hard cap


def _sanitize_filename(raw: str, fallback: str) -> str:
    """Strip path components and dangerous characters from a filename."""
    import os
    import re as _re

    # Take only the basename (prevent ../../etc/cron.d/backdoor)
    name = os.path.basename(raw).strip()
    # Remove any non-printable or path-special characters
    name = _re.sub(r'[^\w\-.]', '_', name)
    # Must end with .zip
    if not name.endswith(".zip"):
        name += ".zip"
    return name or fallback


def download_exploit(exploit_id: int, output_dir: Path | None = None) -> Path:
    """Download exploit as password-protected ZIP to *output_dir* (default: cwd)."""
    dest_dir = output_dir or Path.cwd()
    fallback_name = f"exploit-{exploit_id}.zip"

    with httpx.Client(timeout=TIMEOUT, headers=_build_headers(), follow_redirects=True) as client:
        with client.stream("GET", _api_url(f"/api/v1/exploits/{exploit_id}/download")) as resp:
            if resp.status_code == 404:
                raise APIError(404, f"Exploit {exploit_id} not found or has no downloadable code")
            if resp.status_code >= 400:
                raise APIError(resp.status_code, f"Download failed: HTTP {resp.status_code}")

            # Sanitize filename from Content-Disposition header
            cd = resp.headers.get("content-disposition", "")
            if "filename=" in cd:
                raw_name = cd.split("filename=")[-1].strip('" ')
                filename = _sanitize_filename(raw_name, fallback_name)
            else:
                filename = fallback_name

            # Stream to disk with size cap to prevent OOM
            out_path = dest_dir / filename
            total = 0
            with open(out_path, "wb") as f:
                for chunk in resp.iter_bytes(chunk_size=8192):
                    total += len(chunk)
                    if total > MAX_DOWNLOAD_SIZE:
                        out_path.unlink(missing_ok=True)
                        raise APIError(413, f"Download exceeds {MAX_DOWNLOAD_SIZE // (1024*1024)} MB limit — aborting")
                    f.write(chunk)

    return out_path


def get_stats() -> Stats:
    """Get platform-wide statistics."""
    with httpx.Client(timeout=TIMEOUT, headers=_build_headers(), follow_redirects=True) as client:
        resp = client.get(_api_url("/api/v1/stats"))
    return Stats.from_dict(_handle_response(resp))


def get_health() -> dict[str, Any]:
    """Get health check info."""
    with httpx.Client(timeout=TIMEOUT, headers=_build_headers(), follow_redirects=True) as client:
        resp = client.get(_api_url("/api/v1/health"))
    return _handle_response(resp)
