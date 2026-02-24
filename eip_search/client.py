"""HTTP client for the EIP API."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import httpx
from rich.console import Console

from eip_search import __version__
from eip_search.config import get_config
from eip_search.models import (
    ExploitBrowseResult,
    ExploitFile,
    ExploitWithCVE,
    SearchResult,
    Stats,
    VulnDetail,
)

console = Console(stderr=True)

# Reusable client headers
USER_AGENT = f"eip-search/{__version__}"
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


def _maybe_json(resp: httpx.Response) -> dict[str, Any]:
    """Best-effort JSON parsing.

    Returns an empty dict if the response isn't JSON or can't be parsed.
    """
    ctype = resp.headers.get("content-type", "")
    if not ctype.startswith("application/json"):
        return {}

    try:
        data = resp.json()
    except ValueError:
        return {}

    if isinstance(data, dict):
        return data
    # Keep the public contract of _handle_response() returning a dict
    return {"data": data}


def _handle_response(resp: httpx.Response) -> dict[str, Any]:
    """Check response status and return parsed JSON."""
    data = _maybe_json(resp)

    if resp.status_code == 404:
        raise APIError(404, data.get("message", "Not found"))

    if resp.status_code == 429:
        retry_after_raw = resp.headers.get("Retry-After", "")
        retry_after = 60
        try:
            if retry_after_raw:
                retry_after = int(retry_after_raw)
        except ValueError:
            retry_after = 60

        message = data.get("message") or f"Rate limited. Try again in {retry_after}s."
        raise APIError(429, message, retry_after=retry_after)

    if resp.status_code == 422:
        detail = data.get("detail")
        if isinstance(detail, list) and detail:
            err = detail[0]
            loc = err.get("loc", [])
            field = loc[-1] if loc else "parameter"
            msg_text = err.get("msg", "invalid value")
            message = f"Invalid value for '--{field}': {msg_text} (--min-cvss 0-10, --min-epss 0-1)"
        else:
            message = data.get("message") or "Invalid parameter value (check ranges: --min-cvss 0-10, --min-epss 0-1)"
        raise APIError(422, message)

    if resp.status_code >= 400:
        message = data.get("message") or data.get("detail") or f"API error: HTTP {resp.status_code}"
        raise APIError(resp.status_code, message)

    # Success: expect JSON
    if not data:
        try:
            parsed = resp.json()
        except ValueError as exc:
            raise APIError(resp.status_code, "Invalid JSON response from API") from exc
        if isinstance(parsed, dict):
            return parsed
        return {"data": parsed}

    return data


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


def browse_exploits(params: dict[str, Any]) -> ExploitBrowseResult:
    """Browse/search exploits with filters.

    ``params`` maps directly to the /api/v1/exploits query parameters.
    """
    clean = {k: v for k, v in params.items() if v is not None}
    with httpx.Client(timeout=TIMEOUT, headers=_build_headers(), follow_redirects=True) as client:
        resp = client.get(_api_url("/api/v1/exploits"), params=clean)
    return ExploitBrowseResult.from_dict(_handle_response(resp))


def get_vuln_detail(vuln_id: str) -> VulnDetail:
    """Get full vulnerability detail by CVE-ID or EIP-ID."""
    with httpx.Client(timeout=TIMEOUT, headers=_build_headers(), follow_redirects=True) as client:
        resp = client.get(_api_url(f"/api/v1/vulns/{vuln_id}"))
    return VulnDetail.from_dict(_handle_response(resp))


def get_exploit_analysis(exploit_id: int) -> ExploitWithCVE:
    """Get a single exploit with its LLM analysis and CVE context."""
    with httpx.Client(timeout=TIMEOUT, headers=_build_headers(), follow_redirects=True) as client:
        resp = client.get(_api_url(f"/api/v1/exploits/{exploit_id}"))
    return ExploitWithCVE.from_dict(_handle_response(resp))


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


def get_exploit_image(exploit_id: int, filename: str) -> bytes:
    """Download raw image bytes for a file in an exploit."""
    with httpx.Client(timeout=TIMEOUT, headers=_build_headers(), follow_redirects=True) as client:
        resp = client.get(
            _api_url(f"/api/v1/exploits/{exploit_id}/image"),
            params={"file": filename},
        )
    if resp.status_code == 404:
        raise APIError(404, f"Image not found: {filename}")
    if resp.status_code >= 400:
        raise APIError(resp.status_code, f"Failed to fetch image: HTTP {resp.status_code}")
    return resp.content


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


def list_authors(params: dict[str, Any]) -> dict[str, Any]:
    """List exploit authors ranked by exploit count."""
    clean = {k: v for k, v in params.items() if v is not None}
    with httpx.Client(timeout=TIMEOUT, headers=_build_headers(), follow_redirects=True) as client:
        resp = client.get(_api_url("/api/v1/authors"), params=clean)
    return _handle_response(resp)


def get_author(name: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Get author profile with their exploits."""
    from urllib.parse import quote
    clean = {k: v for k, v in (params or {}).items() if v is not None}
    with httpx.Client(timeout=TIMEOUT, headers=_build_headers(), follow_redirects=True) as client:
        resp = client.get(_api_url(f"/api/v1/authors/{quote(name, safe='')}"), params=clean)
    return _handle_response(resp)


def list_cwes() -> dict[str, Any]:
    """List CWE categories ranked by vulnerability count."""
    with httpx.Client(timeout=TIMEOUT, headers=_build_headers(), follow_redirects=True) as client:
        resp = client.get(_api_url("/api/v1/cwe"))
    return _handle_response(resp)


def get_cwe(cwe_id: str) -> dict[str, Any]:
    """Get CWE detail by ID (e.g. 'CWE-79' or '79')."""
    from urllib.parse import quote
    with httpx.Client(timeout=TIMEOUT, headers=_build_headers(), follow_redirects=True) as client:
        resp = client.get(_api_url(f"/api/v1/cwe/{quote(cwe_id, safe='')}"))
    return _handle_response(resp)


def list_vendors() -> dict[str, Any]:
    """List vendors ranked by vulnerability count."""
    with httpx.Client(timeout=TIMEOUT, headers=_build_headers(), follow_redirects=True) as client:
        resp = client.get(_api_url("/api/v1/vendors"))
    return _handle_response(resp)


def list_vendor_products(vendor: str) -> dict[str, Any]:
    """List products for a specific vendor."""
    from urllib.parse import quote
    with httpx.Client(timeout=TIMEOUT, headers=_build_headers(), follow_redirects=True) as client:
        resp = client.get(_api_url(f"/api/v1/vendors/{quote(vendor, safe='')}/products"))
    return _handle_response(resp)


def lookup_alt_id(alt_id: str) -> dict[str, Any]:
    """Resolve an alternate ID (EDB-XXXXX, GHSA-XXXXX) to its CVE."""
    with httpx.Client(timeout=TIMEOUT, headers=_build_headers(), follow_redirects=True) as client:
        resp = client.get(_api_url("/api/v1/lookup"), params={"alt_id": alt_id})
    return _handle_response(resp)
