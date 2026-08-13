from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from eip_search_v3.client import EipClient, _path_identity, _retry_after
from eip_search_v3.config import Settings
from eip_search_v3.errors import (
    InputError,
    LocalFileError,
    NotFoundError,
    RateLimitedError,
    TransportError,
    UnavailableError,
)


def _traceback_local_text(exc: BaseException) -> str:
    chunks: list[str] = []
    current = exc.__traceback__
    while current is not None:
        if "/eip_search_v3/" in current.tb_frame.f_code.co_filename:
            for value in current.tb_frame.f_locals.values():
                if isinstance(value, (str, bytes, dict, list, tuple, set, frozenset)):
                    chunks.append(repr(value))
        current = current.tb_next
    return "\n".join(chunks)


def _exception_graph_text(exc: BaseException) -> str:
    chunks: list[str] = []
    current: BaseException | None = exc
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chunks.extend((str(current), repr(current), repr(current.__dict__)))
        current = current.__cause__ or current.__context__
    return "\n".join(chunks)


def settings(*, maximum: int = 2 * 1024 * 1024) -> Settings:
    return Settings("https://api.example", 2.0, maximum)


def json_response(request: httpx.Request, payload: object, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=payload, request=request)


def test_endpoint_paths_parameters_and_bodies() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return json_response(request, {"ok": True})

    with EipClient(settings(), httpx.MockTransport(handler)) as client:
        client.readiness()
        client.statistics()
        client.statistics_trends()
        client.search_vulnerabilities([("severity", "HIGH"), ("severity", "CRITICAL")])
        client.vulnerability("GHSA-ab/c")
        client.directory("vendors", [("q", "Micro soft")])
        client.weakness("CWE-79")
        client.author(42)
        client.search_pocs([("association", "unlinked")])
        client.poc("repository:git/x")
        client.artifact("repository:git/x")
        client.search_labs([("analysis", "available")])
        client.code_search({"q": "exec(", "limit": 2})
        client.stix_vulnerability("CVE-2024-3400", mapping="v1")
        client.stix_vulnerability("CVE-2024-3400", mapping="v2")
        client.stix_exploit(123)

    assert seen[3].url.query.decode() == "severity=HIGH&severity=CRITICAL"
    assert seen[4].url.raw_path.endswith(b"/GHSA-ab%2Fc")
    assert seen[9].url.raw_path.endswith(b"/repository%3Agit/x")
    assert json.loads(seen[12].content) == {"q": "exec(", "limit": 2}
    assert seen[-3].url.path.endswith("/CVE-2024-3400/stix")
    assert seen[-2].url.path.endswith("/CVE-2024-3400/stix-v2")
    assert seen[-1].url.path.endswith("/exploits/123/stix")
    assert _path_identity("a:b/c d") == "a%3Ab/c%20d"
    assert _path_identity("../admin") == "%2E%2E/admin"
    with pytest.raises(InputError, match="unsupported directory"):
        EipClient(settings(), httpx.MockTransport(handler)).directory("invalid")
    assert all(request.headers["Accept-Encoding"] == "identity" for request in seen)


def test_client_ignores_implicit_proxy_and_netrc_environment() -> None:
    transport = httpx.MockTransport(lambda request: json_response(request, {}))
    with EipClient(settings(), transport) as client:
        assert client._client._trust_env is False


def test_request_timeout_keeps_connect_and_pool_caps() -> None:
    seen: list[dict[str, float]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.extensions["timeout"])
        return json_response(request, {})

    configured = Settings("https://api.example", 30.0, 2 * 1024 * 1024)
    with EipClient(configured, httpx.MockTransport(handler)) as client:
        client.readiness()
    assert seen[0]["connect"] <= 10.0
    assert seen[0]["pool"] <= 10.0
    assert 29.0 < seen[0]["read"] <= 30.0
    assert 29.0 < seen[0]["write"] <= 30.0


@pytest.mark.parametrize(
    ("status", "exception"),
    [
        (400, InputError),
        (404, NotFoundError),
        (429, RateLimitedError),
        (503, UnavailableError),
        (500, UnavailableError),
    ],
)
def test_http_status_mapping(status: int, exception: type[Exception], monkeypatch) -> None:
    monkeypatch.setattr("eip_search_v3.client.time.sleep", lambda _value: None)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status,
            json={"detail": "specific failure"},
            headers={"Retry-After": "0"},
            request=request,
        )

    with EipClient(settings(), httpx.MockTransport(handler)) as client:
        with pytest.raises(exception, match="specific failure"):
            client.readiness()


def test_validation_detail_and_non_json_fail_cleanly() -> None:
    responses = iter(
        [
            (422, {"detail": [{"loc": ["query", "limit"], "msg": "too large"}]}),
            (200, b"html"),
            (200, b"{"),
            (200, b"[]"),
            (200, b'{"score": NaN}'),
        ]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        status, body = next(responses)
        if isinstance(body, dict):
            return json_response(request, body, status)
        media = "application/json" if body != b"html" else "text/html"
        return httpx.Response(
            status, content=body, headers={"Content-Type": media}, request=request
        )

    with EipClient(settings(), httpx.MockTransport(handler)) as client:
        with pytest.raises(InputError, match="query.limit: too large"):
            client.readiness()
        with pytest.raises(UnavailableError, match="non-JSON"):
            client.readiness()
        with pytest.raises(UnavailableError, match="invalid JSON"):
            client.readiness()
        with pytest.raises(UnavailableError, match="unexpected JSON shape"):
            client.readiness()
        with pytest.raises(UnavailableError, match="invalid JSON"):
            client.readiness()


def test_transport_failure_is_concise(monkeypatch) -> None:
    monkeypatch.setattr("eip_search_v3.client.time.sleep", lambda _value: None)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    with EipClient(settings(), httpx.MockTransport(handler)) as client:
        with pytest.raises(TransportError, match="unreachable") as caught:
            client.readiness()
    assert caught.value.__cause__ is None


def test_mislabeled_compressed_error_preserves_http_status() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            stream=httpx.ByteStream(b"<html>blocked</html>"),
            headers={"Content-Type": "text/html", "Content-Encoding": "gzip"},
            request=request,
        )

    with EipClient(settings(), httpx.MockTransport(handler)) as client:
        with pytest.raises(UnavailableError, match="HTTP 403 Forbidden") as caught:
            client.readiness()
    assert caught.value.status_code == 403


def test_broken_error_body_preserves_http_status() -> None:
    class Broken(httpx.SyncByteStream):
        def __iter__(self):
            yield b"<html>"
            raise httpx.ReadError("truncated")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            stream=Broken(),
            headers={"Content-Type": "text/html"},
            request=request,
        )

    with EipClient(settings(), httpx.MockTransport(handler)) as client:
        with pytest.raises(UnavailableError, match="HTTP 403 Forbidden") as caught:
            client.readiness()
    assert caught.value.status_code == 403


def test_slow_error_body_preserves_http_status_after_deadline(monkeypatch) -> None:
    clock = [0.0]
    monkeypatch.setattr("eip_search_v3.client.time.monotonic", lambda: clock[0])

    class Slow(httpx.SyncByteStream):
        def __iter__(self):
            clock[0] = 3.0
            yield b'{"detail":"busy"}'

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            503,
            stream=Slow(),
            headers={"Content-Type": "application/json"},
            request=request,
        )

    with EipClient(settings(), httpx.MockTransport(handler)) as client:
        with pytest.raises(UnavailableError) as caught:
            client.readiness()
    assert caught.value.status_code == 503


def test_compressed_success_is_rejected_before_decoding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            stream=httpx.ByteStream(b"not-really-gzip"),
            headers={"Content-Type": "application/json", "Content-Encoding": "gzip"},
            request=request,
        )

    with EipClient(settings(), httpx.MockTransport(handler)) as client:
        with pytest.raises(UnavailableError, match="unsupported content encoding"):
            client.readiness()


def test_total_deadline_stops_a_dripping_response(monkeypatch) -> None:
    clock = [0.0]
    monkeypatch.setattr("eip_search_v3.client.time.monotonic", lambda: clock[0])

    class Drip(httpx.SyncByteStream):
        def __iter__(self):
            for chunk in (b'{"', b'ok', b'":true}'):
                clock[0] += 1.0
                yield chunk

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            stream=Drip(),
            headers={"Content-Type": "application/json"},
            request=request,
        )

    with EipClient(settings(), httpx.MockTransport(handler)) as client:
        with pytest.raises(TransportError, match="total timeout"):
            client.readiness()


def test_response_received_after_deadline_is_closed(monkeypatch) -> None:
    clock = [0.0]
    monkeypatch.setattr("eip_search_v3.client.time.monotonic", lambda: clock[0])

    class Tracked(httpx.SyncByteStream):
        closed = False

        def __iter__(self):
            yield b"{}"

        def close(self) -> None:
            self.closed = True

    stream = Tracked()

    def handler(request: httpx.Request) -> httpx.Response:
        clock[0] = 3.0
        return httpx.Response(
            200,
            stream=stream,
            headers={"Content-Type": "application/json"},
            request=request,
        )

    with EipClient(settings(), httpx.MockTransport(handler)) as client:
        with pytest.raises(TransportError, match="total timeout"):
            client.readiness()
    assert stream.closed is True


def test_stream_read_error_maps_to_transport_error() -> None:
    class Broken(httpx.SyncByteStream):
        def __iter__(self):
            yield b'{"ok":'
            raise httpx.ReadError("stream failed")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            stream=Broken(),
            headers={"Content-Type": "application/json"},
            request=request,
        )

    with EipClient(settings(), httpx.MockTransport(handler)) as client:
        with pytest.raises(TransportError, match="response stream failed"):
            client.readiness()


def test_retry_delay_that_does_not_fit_preserves_the_status_error(monkeypatch) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr("eip_search_v3.client.time.monotonic", lambda: 0.0)
    monkeypatch.setattr("eip_search_v3.client.time.sleep", sleeps.append)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            503,
            json={"detail": "busy"},
            headers={"Retry-After": "2"},
            request=request,
        )

    with EipClient(settings(), httpx.MockTransport(handler)) as client:
        with pytest.raises(UnavailableError, match="busy") as caught:
            client.readiness()
    assert caught.value.status_code == 503
    assert sleeps == []


def test_retries_only_transient_capacity_statuses(monkeypatch) -> None:
    monkeypatch.setattr("eip_search_v3.client.time.sleep", lambda _value: None)
    statuses = iter([503, 200, 403])
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        status = next(statuses)
        return httpx.Response(
            status,
            json={"status": "ready"} if status == 200 else {"detail": "failure"},
            request=request,
        )

    with EipClient(settings(), httpx.MockTransport(handler)) as client:
        assert client.readiness()["status"] == "ready"
        assert calls == 2
        with pytest.raises(UnavailableError):
            client.readiness()
        assert calls == 3


def test_protected_file_flow_contains_token() -> None:
    token = "short-lived-super-secret"
    seen: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body)
        if request.url.path.endswith("/poc-access"):
            return json_response(request, {"token": token})
        if request.url.path.endswith("/poc-files"):
            return json_response(request, {"artifact_id": "7", "items": []})
        return httpx.Response(
            422,
            json={"detail": f"bad token {token}"},
            request=request,
        )

    with EipClient(settings(), httpx.MockTransport(handler)) as client:
        assert client.poc_files("7")["artifact_id"] == "7"
        with pytest.raises(InputError) as caught:
            client.poc_file("7", "bad")
    assert seen[0] == {"artifact_id": "7"}
    assert seen[1] == {"token": token}
    assert seen[3] == {"token": token, "path": "bad"}
    assert token not in str(caught.value)
    assert caught.value.__cause__ is None


def test_protected_response_and_error_graph_never_expose_the_token() -> None:
    token = "short-lived-super-secret"
    request_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        if request.url.path.endswith("/poc-access"):
            return json_response(request, {"token": token})
        if request_count == 2:
            return json_response(
                request,
                {"artifact_id": token, "items": [{"path": f"README-{token}.md"}]},
            )
        return httpx.Response(422, json={"detail": f"token {token} rejected"}, request=request)

    with EipClient(settings(), httpx.MockTransport(handler)) as client:
        payload = client.poc_files("7")
        assert token not in repr(payload)
        assert "[redacted access token]" in repr(payload)
        with pytest.raises(InputError) as caught:
            client.poc_file("7", "bad")
    assert token not in str(caught.value)
    assert token not in _traceback_local_text(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_protected_transport_failure_drops_the_token_bearing_request() -> None:
    token = "short-lived-transport-secret"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/poc-access"):
            return json_response(request, {"token": token})
        raise httpx.ConnectError(f"connection lost for {token}", request=request)

    with EipClient(settings(), httpx.MockTransport(handler)) as client:
        with pytest.raises(TransportError) as caught:
            client.poc_files("7")
    assert token not in _exception_graph_text(caught.value)
    assert token not in _traceback_local_text(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_download_stream_filename_overwrite_and_cleanup(tmp_path: Path) -> None:
    token = "download-token"
    archive = b"PK\x03\x04encrypted"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/poc-access"):
            return json_response(request, {"token": token})
        return httpx.Response(
            200,
            content=archive,
            headers={
                "Content-Type": "application/zip",
                "Content-Disposition": 'attachment; filename="../../hostile name.zip"',
            },
            request=request,
        )

    with EipClient(settings(), httpx.MockTransport(handler)) as client:
        result = client.download_poc("7", tmp_path, force=False)
        destination = Path(result["path"])
        assert destination.name == "hostile_name.zip"
        assert destination.read_bytes() == archive
        assert result["password"] == "eip"
        with pytest.raises(LocalFileError, match="overwrite"):
            client.download_poc("7", destination, force=False)
        result = client.download_poc("7", destination, force=True)
        assert Path(result["path"]).read_bytes() == archive
    assert not list(tmp_path.glob("*.part"))


def test_download_bounds_and_media_types(tmp_path: Path) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if request.url.path.endswith("/poc-access"):
            return json_response(request, {"token": "download-token"})
        if calls == 2:
            return httpx.Response(
                200,
                content=b"x" * 11,
                headers={"Content-Type": "application/zip"},
                request=request,
            )
        return httpx.Response(
            200, content=b"not zip", headers={"Content-Type": "text/plain"}, request=request
        )

    with EipClient(settings(maximum=10), httpx.MockTransport(handler)) as client:
        with pytest.raises(LocalFileError, match="exceeded"):
            client.download_poc("7", tmp_path / "large.zip")
        with pytest.raises(UnavailableError, match="content type"):
            client.download_poc("7", tmp_path / "bad.zip")
    assert not list(tmp_path.glob("*.part"))


def test_download_parent_failure_is_a_local_file_error(tmp_path: Path) -> None:
    parent = tmp_path / "not-a-directory"
    parent.write_text("occupied")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/poc-access"):
            return json_response(request, {"token": "download-token"})
        return httpx.Response(
            200,
            content=b"PK\x03\x04encrypted",
            headers={"Content-Type": "application/zip"},
            request=request,
        )

    with EipClient(settings(), httpx.MockTransport(handler)) as client:
        with pytest.raises(LocalFileError, match="Cannot write"):
            client.download_poc("7", parent / "poc.zip")


def test_download_filename_cannot_echo_the_access_token(tmp_path: Path) -> None:
    token = "download-token-secret"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/poc-access"):
            return json_response(request, {"token": token})
        return httpx.Response(
            200,
            content=b"PK\x03\x04encrypted",
            headers={
                "Content-Type": "application/zip",
                "Content-Disposition": f'attachment; filename="{token}.zip"',
            },
            request=request,
        )

    with EipClient(settings(), httpx.MockTransport(handler)) as client:
        result = client.download_poc("7", tmp_path)
    assert token not in result["path"]
    assert token not in Path(result["path"]).name


def test_download_error_traceback_drops_token_bearing_headers(tmp_path: Path) -> None:
    token = "download-token-secret"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/poc-access"):
            return json_response(request, {"token": token})
        return httpx.Response(
            200,
            content=b"not an archive",
            headers={"Content-Type": f"application/{token}"},
            request=request,
        )

    with EipClient(settings(), httpx.MockTransport(handler)) as client:
        with pytest.raises(UnavailableError) as caught:
            client.download_poc("7", tmp_path / "poc.zip")
    assert token not in _traceback_local_text(caught.value)
    assert token not in _exception_graph_text(caught.value)


def test_download_rejects_compression_before_streaming(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/poc-access"):
            return json_response(request, {"token": "download-token"})
        return httpx.Response(
            200,
            stream=httpx.ByteStream(b"not-really-gzip"),
            headers={"Content-Type": "application/zip", "Content-Encoding": "gzip"},
            request=request,
        )

    with EipClient(settings(), httpx.MockTransport(handler)) as client:
        with pytest.raises(UnavailableError, match="unsupported content encoding"):
            client.download_poc("7", tmp_path / "poc.zip")


def test_total_deadline_stops_a_dripping_download(monkeypatch, tmp_path: Path) -> None:
    clock = [0.0]
    monkeypatch.setattr("eip_search_v3.client.time.monotonic", lambda: clock[0])

    class Drip(httpx.SyncByteStream):
        def __iter__(self):
            for chunk in (b"PK", b"\x03\x04", b"payload"):
                clock[0] += 1.0
                yield chunk

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/poc-access"):
            return json_response(request, {"token": "download-token"})
        return httpx.Response(
            200,
            stream=Drip(),
            headers={"Content-Type": "application/zip"},
            request=request,
        )

    destination = tmp_path / "poc.zip"
    with EipClient(settings(), httpx.MockTransport(handler)) as client:
        with pytest.raises(TransportError, match="total timeout"):
            client.download_poc("7", destination)
    assert not destination.exists()
    assert not list(tmp_path.glob("*.part"))


def test_screenshot_download(tmp_path: Path) -> None:
    responses = iter([("image/png", b"png"), ("text/plain", b"bad")])

    def handler(request: httpx.Request) -> httpx.Response:
        media, body = next(responses)
        return httpx.Response(200, content=body, headers={"Content-Type": media}, request=request)

    with EipClient(settings(), httpx.MockTransport(handler)) as client:
        result = client.download_screenshot(42, tmp_path, force=False)
        assert Path(result["path"]).name == "lab-42.png"
        with pytest.raises(UnavailableError, match="content type"):
            client.download_screenshot(42, tmp_path / "bad", force=False)


def test_screenshot_stream_error_maps_to_transport_and_cleans_up(tmp_path: Path) -> None:
    class Broken(httpx.SyncByteStream):
        def __iter__(self):
            yield b"partial"
            raise httpx.ReadError("stream failed")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            stream=Broken(),
            headers={"Content-Type": "image/png"},
            request=request,
        )

    destination = tmp_path / "lab.png"
    with EipClient(settings(), httpx.MockTransport(handler)) as client:
        with pytest.raises(TransportError, match="response stream failed"):
            client.download_screenshot(42, destination)
    assert not destination.exists()
    assert not list(tmp_path.glob("*.part"))


def test_retry_after_parsing() -> None:
    assert _retry_after({"Retry-After": "4"}) == 4
    assert _retry_after({"Retry-After": "-2"}) == 0
    assert (
        _retry_after(
            {"Retry-After": "Wed, 01 Jan 2025 00:00:04 GMT"},
            now=datetime(2025, 1, 1, tzinfo=UTC),
        )
        == 4
    )
    assert _retry_after({"Retry-After": "later"}) is None
    assert _retry_after({}) is None
