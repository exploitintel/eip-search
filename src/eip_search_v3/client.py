"""Bounded HTTP client for the public EIP v3 API."""

from __future__ import annotations

import hashlib
import json
import math
import os
import tempfile
import time
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from . import __version__
from .config import Settings
from .errors import (
    CliError,
    InputError,
    LocalFileError,
    NotFoundError,
    RateLimitedError,
    TransportError,
    UnavailableError,
)
from .safety import safe_filename

MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_ERROR_BYTES = 64 * 1024
MAX_SCREENSHOT_BYTES = 15 * 1024 * 1024


def _path_identity(value: str) -> str:
    segments = []
    for segment in value.split("/"):
        encoded = quote(segment, safe="")
        if segment and not segment.strip("."):
            encoded = encoded.replace(".", "%2E")
        segments.append(encoded)
    return "/".join(segments)


def _retry_after(headers: Mapping[str, str], *, now: datetime | None = None) -> int | None:
    raw = headers.get("Retry-After")
    if raw is None:
        return None
    try:
        value = int(raw)
    except ValueError:
        try:
            deadline = parsedate_to_datetime(raw)
        except (TypeError, ValueError, OverflowError):
            return None
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=UTC)
        current = now or datetime.now(UTC)
        return max(0, math.ceil((deadline - current).total_seconds()))
    return max(0, value)


def _error_detail(response: httpx.Response, secret: str | None = None) -> str:
    text = ""
    try:
        payload = response.json()
    except ValueError:
        payload = None
    if isinstance(payload, dict):
        detail = payload.get("detail") or payload.get("message")
        if isinstance(detail, list):
            parts = []
            for item in detail[:3]:
                if isinstance(item, dict):
                    location = ".".join(str(part) for part in item.get("loc", ()))
                    parts.append(f"{location}: {item.get('msg', 'invalid value')}")
            text = "; ".join(parts)
        elif detail is not None:
            text = str(detail)
    if not text:
        text = f"HTTP {response.status_code} {response.reason_phrase}".strip()
    if secret:
        text = text.replace(secret, "[redacted]")
    return " ".join(text.split())[:1_000]


def _suggested_filename(
    response: httpx.Response, fallback: str, *, secret: str | None = None
) -> str:
    header = response.headers.get("Content-Disposition", "")
    raw = fallback
    for part in header.split(";"):
        key, separator, value = part.strip().partition("=")
        if separator and key.lower() == "filename":
            raw = value.strip().strip('"')
            break
    if secret:
        raw = raw.replace(secret, "redacted-access-token")
    return safe_filename(raw, fallback)


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _read_limited(
    response: httpx.Response,
    maximum: int,
    *,
    truncate: bool = False,
    deadline: float | None = None,
    target: str = "EIP API",
) -> bytes:
    _require_identity_encoding(response)
    chunks: list[bytes] = []
    size = 0
    try:
        for chunk in response.iter_bytes(64 * 1024):
            _require_before_deadline(deadline, target)
            remaining = maximum - size
            if len(chunk) > remaining:
                if truncate and remaining > 0:
                    chunks.append(chunk[:remaining])
                if truncate:
                    break
                raise UnavailableError(f"EIP API response exceeded the {maximum}-byte limit")
            chunks.append(chunk)
            size += len(chunk)
    except httpx.RequestError as exc:
        raise TransportError(f"EIP API response stream failed at {target}: {exc}") from None
    return b"".join(chunks)


def _require_identity_encoding(response: httpx.Response) -> None:
    encoding = response.headers.get("Content-Encoding", "identity").strip().casefold()
    if encoding not in {"", "identity"}:
        raise UnavailableError("EIP API returned an unsupported content encoding")


def _require_before_deadline(deadline: float | None, target: str) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise TransportError(f"EIP API exceeded its total timeout at {target}")


def _remaining_before_deadline(deadline: float, target: str) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TransportError(f"EIP API exceeded its total timeout at {target}")
    return remaining


def _sleep_before_deadline(seconds: float, deadline: float, target: str) -> None:
    remaining = _remaining_before_deadline(deadline, target)
    if seconds >= remaining:
        raise TransportError(f"EIP API exceeded its total timeout at {target}")
    time.sleep(seconds)
    _require_before_deadline(deadline, target)


def _redact_secret(value: Any, secret: str) -> Any:
    if isinstance(value, str):
        return value.replace(secret, "[redacted access token]")
    if isinstance(value, list):
        return [_redact_secret(item, secret) for item in value]
    if isinstance(value, dict):
        return {
            _redact_secret(key, secret) if isinstance(key, str) else key: _redact_secret(
                item, secret
            )
            for key, item in value.items()
        }
    return value


def _sanitized_protected_error(exc: Exception, secret: str) -> CliError:
    message = str(exc).replace(secret, "[redacted access token]")
    if isinstance(exc, NotFoundError):
        return NotFoundError(message)
    if isinstance(exc, InputError):
        return InputError(message, exc.status_code)
    if isinstance(exc, RateLimitedError):
        return RateLimitedError(message, exc.retry_after)
    if isinstance(exc, UnavailableError):
        return UnavailableError(message, exc.status_code, exc.retry_after)
    if isinstance(exc, TransportError):
        return TransportError(message)
    if isinstance(exc, LocalFileError):
        return LocalFileError(message)
    return TransportError(f"Protected EIP API request failed: {message}")


class EipClient:
    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None) -> None:
        self.settings = settings
        timeout = httpx.Timeout(
            settings.timeout_seconds,
            connect=min(10.0, settings.timeout_seconds),
            pool=min(10.0, settings.timeout_seconds),
        )
        try:
            self._client = httpx.Client(
                base_url=settings.base_url,
                timeout=timeout,
                follow_redirects=False,
                headers={
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                    "User-Agent": f"eip-search/{__version__}",
                },
                trust_env=False,
                transport=transport,
            )
        except httpx.InvalidURL as exc:
            raise InputError(f"Invalid API base URL: {exc}") from None

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> EipClient:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _raise_for_status(self, response: httpx.Response, *, secret: str | None = None) -> None:
        if response.status_code < 300:
            return
        detail = _error_detail(response, secret)
        retry_after = _retry_after(response.headers)
        if response.status_code == 404:
            raise NotFoundError(detail) from None
        if response.status_code in {400, 405, 409, 422}:
            raise InputError(detail, response.status_code) from None
        if response.status_code == 429:
            raise RateLimitedError(detail, retry_after) from None
        if response.status_code in {502, 503, 504}:
            raise UnavailableError(detail, response.status_code, retry_after) from None
        raise UnavailableError(detail, response.status_code, retry_after) from None

    def _send(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | Iterable[tuple[str, Any]] | None = None,
        body: Mapping[str, Any] | None = None,
        secret: str | None = None,
        accept: str | None = None,
        retryable: bool = True,
        stream: bool = False,
    ) -> httpx.Response:
        headers = {"Accept": accept} if accept else None
        attempts = 2 if retryable else 1
        deadline = time.monotonic() + self.settings.timeout_seconds
        for attempt in range(attempts):
            try:
                remaining = _remaining_before_deadline(deadline, self.settings.base_url)
                request = self._client.build_request(
                    method,
                    path,
                    params=params,
                    json=body,
                    headers=headers,
                    timeout=httpx.Timeout(
                        remaining,
                        connect=min(10.0, remaining),
                        pool=min(10.0, remaining),
                    ),
                )
                response = self._client.send(request, stream=stream)
                try:
                    _require_before_deadline(deadline, self.settings.base_url)
                except TransportError:
                    response.close()
                    raise
                response.extensions["eip_total_deadline"] = deadline
                if response.status_code >= 300 and stream:
                    try:
                        encoding = response.headers.get("Content-Encoding", "identity")
                        if encoding.strip().casefold() in {"", "identity"}:
                            try:
                                error_body = _read_limited(
                                    response,
                                    MAX_ERROR_BYTES,
                                    truncate=True,
                                    deadline=deadline,
                                    target=self.settings.base_url,
                                )
                            except (TransportError, UnavailableError):
                                # The received status remains authoritative when
                                # an optional error body is truncated or broken.
                                error_body = b""
                        else:
                            # The status is authoritative even when an edge has
                            # mislabeled the body and decoding it would fail.
                            error_body = b""
                    finally:
                        response.close()
                    response_headers = {
                        key: value
                        for key, value in response.headers.items()
                        if key.casefold() not in {"content-encoding", "content-length"}
                    }
                    response = httpx.Response(
                        response.status_code,
                        headers=response_headers,
                        content=error_body,
                        request=request,
                    )
                try:
                    self._raise_for_status(response, secret=secret)
                except Exception:
                    response.close()
                    raise
                return response
            except (RateLimitedError, UnavailableError) as exc:
                if attempt + 1 >= attempts:
                    raise
                if isinstance(exc, UnavailableError) and exc.status_code not in {502, 503, 504}:
                    raise
                wait = exc.retry_after
                if wait is None:
                    wait = 1
                if wait > 2:
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0 or wait >= remaining:
                    raise
                _sleep_before_deadline(wait, deadline, self.settings.base_url)
            except httpx.TimeoutException:
                if attempt + 1 >= attempts:
                    raise TransportError(f"EIP API timed out at {self.settings.base_url}") from None
                _sleep_before_deadline(0.25, deadline, self.settings.base_url)
            except httpx.InvalidURL as exc:
                reason = str(exc)
                if secret:
                    reason = reason.replace(secret, "[redacted]")
                raise InputError(f"Invalid API request URL: {reason}") from None
            except httpx.RequestError as exc:
                if attempt + 1 >= attempts:
                    reason = str(exc)
                    if secret:
                        reason = reason.replace(secret, "[redacted]")
                    raise TransportError(
                        f"EIP API unreachable at {self.settings.base_url}: {reason}"
                    ) from None
                _sleep_before_deadline(0.25, deadline, self.settings.base_url)
        raise AssertionError("request attempt loop exhausted")

    def _json(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | Iterable[tuple[str, Any]] | None = None,
        body: Mapping[str, Any] | None = None,
        secret: str | None = None,
        retryable: bool = True,
        accept: str | None = None,
    ) -> dict[str, Any]:
        response = self._send(
            method,
            path,
            params=params,
            body=body,
            secret=secret,
            retryable=retryable,
            accept=accept,
            stream=True,
        )
        try:
            content_type = response.headers.get("Content-Type", "").lower()
            if "json" not in content_type:
                raise UnavailableError("EIP API returned a non-JSON response")
            body_bytes = _read_limited(
                response,
                MAX_JSON_BYTES,
                deadline=response.extensions.get("eip_total_deadline"),
                target=self.settings.base_url,
            )
        finally:
            response.close()
        try:
            payload = json.loads(body_bytes, parse_constant=_reject_json_constant)
        except (json.JSONDecodeError, ValueError, RecursionError):
            raise UnavailableError("EIP API returned invalid JSON") from None
        if not isinstance(payload, dict):
            raise UnavailableError("EIP API returned an unexpected JSON shape")
        return payload

    def readiness(self) -> dict[str, Any]:
        return self._json("GET", "/health/ready")

    def statistics(self) -> dict[str, Any]:
        return self._json("GET", "/api/v1/statistics")

    def statistics_trends(self) -> dict[str, Any]:
        return self._json("GET", "/api/v1/statistics/trends")

    def search_vulnerabilities(self, params: Iterable[tuple[str, Any]]) -> dict[str, Any]:
        return self._json("GET", "/api/v1/vulnerabilities", params=params)

    def vulnerability(self, identifier: str) -> dict[str, Any]:
        return self._json("GET", f"/api/v1/vulnerabilities/{quote(identifier, safe='')}")

    def directory(self, name: str, params: Iterable[tuple[str, Any]] = ()) -> dict[str, Any]:
        allowed = {"vendors", "products", "ecosystems", "packages", "weaknesses", "authors"}
        if name not in allowed:
            raise InputError(f"unsupported directory: {name}")
        return self._json("GET", f"/api/v1/{name}", params=params)

    def weakness(self, cwe_id: str) -> dict[str, Any]:
        return self._json("GET", f"/api/v1/weaknesses/{quote(cwe_id, safe='')}")

    def author(self, public_id: int) -> dict[str, Any]:
        return self._json("GET", f"/api/v1/authors/{public_id}")

    def search_pocs(self, params: Iterable[tuple[str, Any]]) -> dict[str, Any]:
        return self._json("GET", "/api/v1/pocs", params=params)

    def poc(self, identity: str) -> dict[str, Any]:
        return self._json("GET", f"/api/v1/pocs/{_path_identity(identity)}")

    def artifact(self, identity: str) -> dict[str, Any]:
        return self._json("GET", f"/api/v1/artifacts/{_path_identity(identity)}")

    def search_labs(self, params: Iterable[tuple[str, Any]]) -> dict[str, Any]:
        return self._json("GET", "/api/v1/labs", params=params)

    def code_search(self, body: Mapping[str, Any]) -> dict[str, Any]:
        return self._json("POST", "/api/v1/poc-code-search", body=body)

    def _access_token(self, identity: str) -> str:
        payload = self._json(
            "POST",
            "/api/v1/poc-access",
            body={"artifact_id": identity},
            retryable=False,
        )
        token = payload.get("token")
        if not isinstance(token, str) or len(token) < 8:
            del payload
            del token
            raise UnavailableError("EIP API did not return a PoC access token")
        del payload
        return token

    def _protected_json(
        self,
        path: str,
        identity: str,
        extra_body: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        token = self._access_token(identity)
        body = {"token": token, **(extra_body or {})}
        failure: CliError | None = None
        result: dict[str, Any] | None = None
        try:
            try:
                payload = self._json(
                    "POST",
                    path,
                    body=body,
                    secret=token,
                    retryable=False,
                )
                result = _redact_secret(payload, token)
                del payload
            except Exception as exc:
                failure = _sanitized_protected_error(exc, token)
        finally:
            body.clear()
            del body
            del token
        if failure is not None:
            raise failure from None
        if result is None:
            raise TransportError("Protected EIP API request returned no result")
        return result

    def poc_files(self, identity: str) -> dict[str, Any]:
        return self._protected_json("/api/v1/poc-files", identity)

    def poc_file(self, identity: str, path: str) -> dict[str, Any]:
        return self._protected_json("/api/v1/poc-file", identity, {"path": path})

    def _write_stream(
        self,
        response: httpx.Response,
        destination: Path,
        *,
        maximum: int,
        force: bool,
    ) -> tuple[Path, int, str]:
        _require_identity_encoding(response)
        deadline = response.extensions.get("eip_total_deadline")
        destination = destination.expanduser()
        temporary: Path | None = None
        size = 0
        digest = hashlib.sha256()
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists() and not force:
                raise LocalFileError(f"Refusing to overwrite {destination}; pass --force")
            descriptor, raw_path = tempfile.mkstemp(
                prefix=f".{destination.name}.", suffix=".part", dir=destination.parent
            )
            temporary = Path(raw_path)
            with os.fdopen(descriptor, "wb") as handle:
                try:
                    for chunk in response.iter_bytes(64 * 1024):
                        _require_before_deadline(deadline, self.settings.base_url)
                        size += len(chunk)
                        if size > maximum:
                            raise LocalFileError(
                                f"Download exceeded the configured {maximum}-byte limit"
                            )
                        handle.write(chunk)
                        digest.update(chunk)
                except httpx.RequestError as exc:
                    raise TransportError(
                        f"EIP API response stream failed at {self.settings.base_url}: {exc}"
                    ) from None
                handle.flush()
                os.fsync(handle.fileno())
            if force:
                os.replace(temporary, destination)
            else:
                try:
                    os.link(temporary, destination)
                except FileExistsError:
                    raise LocalFileError(
                        f"Refusing to overwrite {destination}; pass --force"
                    ) from None
                temporary.unlink()
            temporary = None
            return destination, size, f"sha256:{digest.hexdigest()}"
        except OSError as exc:
            raise LocalFileError(f"Cannot write {destination}: {exc}") from None
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def download_poc(
        self,
        identity: str,
        output: Path | None,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        token = self._access_token(identity)
        body = {"token": token}
        response: httpx.Response | None = None
        failure: CliError | None = None
        result: dict[str, Any] | None = None
        try:
            try:
                response = self._send(
                    "POST",
                    "/api/v1/poc-download",
                    body=body,
                    secret=token,
                    accept="application/zip",
                    retryable=False,
                    stream=True,
                )
                if "application/zip" not in response.headers.get("Content-Type", "").lower():
                    raise UnavailableError("EIP API returned an unexpected download content type")
                filename = _suggested_filename(response, "eip-poc.zip", secret=token)
                destination = output or Path.cwd() / filename
                if destination.exists() and destination.is_dir():
                    destination /= filename
                path, size, digest = self._write_stream(
                    response,
                    destination,
                    maximum=self.settings.max_download_bytes,
                    force=force,
                )
                result = {
                    "path": str(path),
                    "size": size,
                    "sha256": digest,
                    "password": "eip",
                }
            except Exception as exc:
                failure = _sanitized_protected_error(exc, token)
        finally:
            if response is not None:
                response.close()
            body.clear()
            del response
            del body
            del token
        if failure is not None:
            raise failure from None
        if result is None:
            raise TransportError("Protected EIP API download returned no result")
        return result

    def download_screenshot(
        self,
        public_id: int,
        output: Path,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        response = self._send(
            "GET",
            f"/api/v1/labs/{public_id}/screenshot",
            accept="image/png,image/jpeg",
            stream=True,
        )
        try:
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].lower()
            suffix = (
                ".png"
                if content_type == "image/png"
                else ".jpg"
                if content_type == "image/jpeg"
                else None
            )
            if suffix is None:
                raise UnavailableError("EIP API returned an unexpected screenshot content type")
            destination = output.expanduser()
            if destination.exists() and destination.is_dir():
                destination /= f"lab-{public_id}{suffix}"
            path, size, digest = self._write_stream(
                response, destination, maximum=MAX_SCREENSHOT_BYTES, force=force
            )
        finally:
            response.close()
        return {"path": str(path), "size": size, "sha256": digest, "media_type": content_type}

    def stix_vulnerability(self, identifier: str, *, mapping: str) -> dict[str, Any]:
        suffix = "stix" if mapping == "v1" else "stix-v2"
        return self._json(
            "GET",
            f"/api/v1/vulnerabilities/{quote(identifier, safe='')}/{suffix}",
            accept="application/stix+json;version=2.1,application/json",
        )

    def stix_exploit(self, public_id: int) -> dict[str, Any]:
        return self._json(
            "GET",
            f"/api/v1/exploits/{public_id}/stix",
            accept="application/stix+json;version=2.1,application/json",
        )
