"""Collector boundary contracts; every credential and network endpoint is synthetic."""

import asyncio
import json
import re
import shutil
import ssl
import subprocess
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import httpx
import pytest


INPUT = "https://example.invalid/synthetic"
TOKEN = "synthetic-test-token"
MAX_BYTES = 1024 * 1024


def page_payload(**changes):
    return {
        "input_url": INPUT, "final_url": INPUT, "redirect_chain": [],
        "status_code": 200, "content_type": "text/html; charset=utf-8",
        "html": "<html><title>합성</title><body>synthetic</body></html>",
        "title": "합성", "elapsed_ms": 12, "failures": [],
    } | changes


class RawStream(httpx.AsyncByteStream):
    """Expose raw byte consumption and closure, including an unread tail."""

    def __init__(self, parts):
        self.parts = parts
        self.read = 0
        self.closed = False

    async def __aiter__(self):
        for part in self.parts:
            self.read += 1
            yield part

    async def aclose(self):
        self.closed = True


def raw_response(payload=None, *, raw=None, status=200, headers=None, stream=None):
    if raw is None:
        raw = json.dumps(payload if payload is not None else page_payload(), ensure_ascii=False).encode("utf-8")
    return httpx.Response(status, headers={"content-type": "application/json"} | (headers or {}),
                          stream=stream or RawStream([raw]))


def invoke(config, handler, *, token_mode="valid", follow_redirects=False):
    from isolation_tests.adapters.collector import collect

    async def call():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                     follow_redirects=follow_redirects, timeout=None) as client:
            result = await collect(config, INPUT, token_mode, client=client)
            # An injected client remains owned by its caller.
            assert not client.is_closed
            return result

    return asyncio.run(call())


def collection_error(config, handler, **kwargs):
    from isolation_tests.adapters.collector import CollectionError

    with pytest.raises(CollectionError) as caught:
        invoke(config, handler, **kwargs)
    error = caught.value
    assert isinstance(error.code, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", error.code)
    assert str(error) == error.code
    return error


def test_success_preserves_collected_fields_and_sends_only_designated_token(configured_collector, monkeypatch):
    from isolation_tests.model import CollectedPage

    monkeypatch.setenv("ISOLATION_TEST_TOKEN", "synthetic-decoy-do-not-use")
    requests = []

    def handler(request):
        requests.append(request)
        return raw_response(page_payload(redirect_chain=["https://example.invalid/first"]))

    page = invoke(configured_collector, handler)
    assert page == CollectedPage(INPUT, INPUT, ("https://example.invalid/first",), 200,
                                 "text/html; charset=utf-8", page_payload()["html"], "합성", 12, ())
    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert str(request.url) == "https://collector.example.invalid/collect"
    assert json.loads(request.content) == {"url": INPUT}
    assert request.headers["authorization"] == f"Bearer {TOKEN}"
    assert request.headers.get("accept-encoding") == "identity"


@pytest.mark.parametrize("mode", ["valid", "missing", "wrong"])
def test_authentication_modes_reach_api_and_preserve_401_classification(configured_collector, mode):
    seen = []

    def handler(request):
        seen.append(request.headers.get("authorization"))
        return raw_response() if seen[-1] == f"Bearer {TOKEN}" else raw_response(status=401, raw=b"synthetic-private-response")

    if mode == "valid":
        assert invoke(configured_collector, handler, token_mode=mode).failures == ()
    else:
        error = collection_error(configured_collector, handler, token_mode=mode)
        assert "synthetic-private-response" not in repr(error)
    assert len(seen) == 1
    if mode == "missing":
        assert seen == [None]
    elif mode == "wrong":
        assert seen[0] is not None and seen[0].startswith("Bearer ") and seen[0] != f"Bearer {TOKEN}"


@pytest.mark.parametrize("mode", ["unknown", "wrong-token", "", None])
def test_undocumented_token_modes_do_not_send_request(configured_collector, mode):
    requests = []
    from isolation_tests.adapters.collector import CollectionError

    with pytest.raises((CollectionError, ValueError)):
        invoke(configured_collector, lambda request: requests.append(request) or raw_response(), token_mode=mode)
    assert requests == []


def test_missing_designated_token_does_not_fall_back_to_other_environment(configured_collector, monkeypatch):
    monkeypatch.delenv("TEST_ONLY_TOKEN")
    monkeypatch.setenv("ISOLATION_TEST_TOKEN", "synthetic-decoy-do-not-use")
    requests = []
    collection_error(configured_collector, lambda request: requests.append(request) or raw_response())
    assert requests == []


def test_unconfigured_api_is_preparation_error_without_network(configured_collector):
    requests = []
    collection_error(replace(configured_collector, collector_url=None),
                     lambda request: requests.append(request) or raw_response())
    assert requests == []


def test_stub_response_is_not_collection_success(configured_collector):
    error = collection_error(configured_collector, lambda request: raw_response(page_payload(
        final_url=None, status_code=None, content_type=None, html="", title=None,
        elapsed_ms=0, failures=["stub_not_collected"])))
    assert error.code == "stub_not_collected"


@pytest.mark.parametrize("field", list(page_payload()))
def test_every_required_response_field_is_checked(configured_collector, field):
    payload = page_payload()
    del payload[field]
    collection_error(configured_collector, lambda request: raw_response(payload))


@pytest.mark.parametrize("changes", [
    {"elapsed_ms": True}, {"elapsed_ms": -1}, {"elapsed_ms": 1.5},
    {"status_code": True}, {"status_code": "200"},
    {"input_url": 7}, {"final_url": []}, {"redirect_chain": INPUT},
    {"redirect_chain": [None]}, {"html": None}, {"title": 7},
    {"content_type": []}, {"failures": "timeout"}, {"failures": [False]},
    {"unexpected": "synthetic-unapproved-field"},
])
def test_mixed_response_types_and_unapproved_keys_are_rejected(configured_collector, changes):
    collection_error(configured_collector, lambda request: raw_response(page_payload(**changes)))


@pytest.mark.parametrize("raw", [b"[]", b"null", b"{}", b"not-json", b"\xff", b'{"elapsed_ms":NaN}'])
def test_utf8_json_and_top_level_schema_are_strict(configured_collector, raw):
    collection_error(configured_collector, lambda request: raw_response(raw=raw))


def test_duplicate_json_keys_do_not_hide_a_bad_field(configured_collector):
    raw = json.dumps(page_payload()).encode()
    raw = raw[:-1] + b',"html":null,"html":"synthetic"}'
    collection_error(configured_collector, lambda request: raw_response(raw=raw))


def test_empty_html_without_remote_failure_is_missing_collection_data(configured_collector):
    collection_error(configured_collector, lambda request: raw_response(page_payload(html="")))


def test_remote_failure_remains_observable_and_separate_from_transport_error(configured_collector):
    page = invoke(configured_collector, lambda request: raw_response(page_payload(
        html="", final_url=None, status_code=None, content_type=None,
        title=None, failures=["collection_timeout"])))
    assert page.html == ""
    assert page.failures == ("collection_timeout",)
    assert page.final_url is None and page.status_code is None


@pytest.mark.parametrize("encoding", ["gzip", "deflate", "br"])
def test_compressed_api_response_is_rejected_before_raw_body_read(configured_collector, encoding):
    stream = RawStream([b"not-actually-compressed"])
    error = collection_error(configured_collector, lambda request: raw_response(
        headers={"content-encoding": encoding}, stream=stream))
    assert error.code == "unsupported_response_encoding"
    assert stream.read == 0 and stream.closed


@pytest.mark.parametrize("claimed_length", ["1", str(MAX_BYTES * 2)])
def test_exact_raw_limit_is_accepted_regardless_of_content_length(configured_collector, claimed_length):
    raw = json.dumps(page_payload()).encode("utf-8")
    stream = RawStream([raw, b" " * (MAX_BYTES - len(raw))])
    page = invoke(configured_collector, lambda request: raw_response(
        stream=stream, headers={"content-length": claimed_length, "content-encoding": "identity"}))
    assert page.html == page_payload()["html"]
    assert stream.closed


def test_one_byte_over_raw_limit_stops_before_unread_tail(configured_collector):
    stream = RawStream([b" " * MAX_BYTES, b"x", b"synthetic-unread-tail"])
    error = collection_error(configured_collector, lambda request: raw_response(stream=stream))
    assert error.code == "runner_response_too_large"
    assert stream.read == 2 and stream.closed


def test_configured_response_limit_cannot_enlarge_hard_one_mib_boundary(configured_collector):
    config = replace(configured_collector, limits=configured_collector.limits | {"runner_response_bytes": MAX_BYTES * 2})
    error = collection_error(config, lambda request: raw_response(stream=RawStream([b" " * (MAX_BYTES + 1)])))
    assert error.code == "runner_response_too_large"


def test_smaller_configured_response_limit_is_enforced(configured_collector):
    config = replace(configured_collector, limits=configured_collector.limits | {"runner_response_bytes": 64})
    error = collection_error(config, lambda request: raw_response(stream=RawStream([b" " * 65])))
    assert error.code == "runner_response_too_large"


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_api_redirect_is_rejected_even_when_injected_client_follows_redirects(configured_collector, status):
    requests = []

    def handler(request):
        requests.append(request)
        if len(requests) > 1:
            return raw_response()
        return raw_response(status=status, headers={"location": "https://other.invalid/capture"})

    collection_error(configured_collector, handler, follow_redirects=True)
    assert [str(request.url) for request in requests] == [configured_collector.collector_url]


def test_http_auth_unavailable_and_malformed_response_have_distinct_safe_codes(configured_collector):
    auth = collection_error(configured_collector, lambda request: raw_response(status=401, raw=b"synthetic-secret-body"))
    unavailable = collection_error(configured_collector, lambda request: raw_response(status=503, raw=b"synthetic-secret-body"))
    malformed = collection_error(configured_collector, lambda request: raw_response(raw=b"synthetic-secret-body"))
    assert len({auth.code, unavailable.code, malformed.code}) == 3
    assert all("synthetic-secret-body" not in str(error) for error in (auth, unavailable, malformed))


def test_request_errors_and_remote_diagnostics_do_not_echo_secrets(configured_collector):
    def broken(request):
        raise httpx.ConnectError(f"Authorization: Bearer {TOKEN}; url={INPUT}?secret=synthetic-query", request=request)

    error = collection_error(configured_collector, broken)
    assert TOKEN not in repr(error) and "synthetic-query" not in repr(error)
    assert "authorization" not in repr(error).lower()
    remote = collection_error(configured_collector, lambda request: raw_response(page_payload(
        html="", failures=[f"Authorization: Bearer {TOKEN}"])))
    assert TOKEN not in repr(remote)


@pytest.mark.parametrize("phase", ["request", "body"])
def test_default_overall_deadline_cancels_injected_client_with_no_timeout(configured_collector, monkeypatch, phase):
    # Accelerate the watchdog after verifying its public budget; keep actual
    # asyncio cancellation and httpx streaming lifecycle in this test.
    real_timeout = asyncio.timeout
    real_wait_for = asyncio.wait_for
    budgets = []
    cancelled = []

    def accelerated_timeout(delay):
        budgets.append(delay)
        return real_timeout(0.03)

    async def accelerated_wait_for(awaitable, timeout):
        budgets.append(timeout)
        return await real_wait_for(awaitable, 0.03)

    async def hang():
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.append(True)

    class HangingStream(RawStream):
        async def __aiter__(self):
            yield b"{"
            await hang()

    stream = HangingStream([])

    async def handler(request):
        if phase == "request":
            await hang()
        return raw_response(stream=stream)

    monkeypatch.setattr(asyncio, "timeout", accelerated_timeout)
    monkeypatch.setattr(asyncio, "wait_for", accelerated_wait_for)
    collection_error(configured_collector, handler)
    assert budgets == [15]
    assert cancelled == [True]
    if phase == "body":
        assert stream.closed


@pytest.mark.parametrize("variant", ["initial-private", "scheme", "userinfo", "normalized-host"])
def test_net07_derives_only_fixed_variants_and_submits_candidate_for_remote_policy(configured_collector, variant):
    from isolation_tests.manifest import load_cases
    from isolation_tests.targets import case_url

    root = Path(__file__).resolve().parents[1]
    case = next(case for case in load_cases(root / "tools/isolation-tests/cases.json") if case.id == "NET-07")
    config = replace(configured_collector, bases={
        "private": "https://192.168.50.12/synthetic-private",
        "forbidden_receiver": "https://receiver.invalid/synthetic-receiver",
    })
    candidate = case_url(case, variant, config, "synthetic-run")
    # Query correlation is allowed; the attack transformations themselves are
    # fixed and come from controlled configuration, never an arbitrary URL list.
    bare = candidate.partition("?")[0]
    expected = {
        "initial-private": "https://192.168.50.12/synthetic-private",
        "scheme": "file:///isolation-test-only",
        "userinfo": "https://isolation-test@receiver.invalid/synthetic-receiver",
        "normalized-host": "https://RECEIVER.INVALID./synthetic-receiver",
    }
    assert bare == expected[variant]
    requests = []

    def handler(request):
        requests.append(json.loads(request.content))
        return raw_response(page_payload(input_url=candidate, html="", final_url=None,
            status_code=None, content_type=None, title=None, failures=["initial_url_rejected"]))

    from isolation_tests.adapters.collector import collect

    async def call():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await collect(config, candidate, client=client)

    page = asyncio.run(call())
    assert requests == [{"url": candidate}]
    assert page.failures == ("initial_url_rejected",)
    # Collection data does not invent receiver/page-opened evidence. A remote
    # failure code alone is not a successful NET-07 enforcement result.
    assert not hasattr(page, "page_opened") and not hasattr(page, "receiver_observed")


def test_net07_does_not_accept_arbitrary_url_as_a_variant(configured_collector):
    from isolation_tests.manifest import load_cases
    from isolation_tests.targets import case_url

    root = Path(__file__).resolve().parents[1]
    case = next(case for case in load_cases(root / "tools/isolation-tests/cases.json") if case.id == "NET-07")
    with pytest.raises(ValueError):
        case_url(case, "https://unregistered.invalid/arbitrary", configured_collector, "synthetic-run")


@pytest.fixture
def tls_material(tmp_path):
    """Two ephemeral CAs and one CA-signed loopback server certificate."""
    directory = tmp_path / "collector-tls"
    directory.mkdir()
    candidates = [shutil.which("openssl"), "C:/Program Files/Git/usr/bin/openssl.exe"]
    openssl = next((str(candidate) for candidate in candidates if candidate and Path(candidate).is_file()), None)
    if openssl is None:
        pytest.fail("real collector TLS tests require an OpenSSL executable")

    def run(*args):
        result = subprocess.run([openssl, *map(str, args)], cwd=directory,
                                capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, f"OpenSSL failed: {result.stderr}"

    ca_config = directory / "ca.cnf"
    ca_config.write_text("[req]\ndistinguished_name=dn\nx509_extensions=ca\n[dn]\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n", encoding="ascii")
    for name in ("trusted", "untrusted"):
        run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", f"/CN=Synthetic {name} collector CA", "-config", ca_config,
            "-keyout", directory / f"{name}.key", "-out", directory / f"{name}.pem")
    run("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
        "-config", ca_config, "-keyout", directory / "server.key", "-out", directory / "server.csr")
    extensions = directory / "server.cnf"
    extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n", encoding="ascii")
    run("x509", "-req", "-in", directory / "server.csr", "-CA", directory / "trusted.pem",
        "-CAkey", directory / "trusted.key", "-CAcreateserial", "-days", "1",
        "-extfile", extensions, "-out", directory / "server.pem")
    return directory


@pytest.fixture
def local_tls_collector(tls_material):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("content-length", 0)))
            requests.append((self.path, self.headers.get("authorization"), json.loads(body)))
            payload = json.dumps(page_payload()).encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(tls_material / "server.pem", tls_material / "server.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://127.0.0.1:{server.server_port}/collect", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def test_real_tls_trusted_control_and_untrusted_ca_do_not_send_body(configured_collector, tls_material, local_tls_collector, monkeypatch):
    from isolation_tests.adapters.collector import CollectionError, collect

    url, requests = local_tls_collector
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("SSL_CERT_FILE", str(tls_material / "untrusted.pem"))
    trusted = replace(configured_collector, collector_url=url, ca_file=tls_material / "trusted.pem")
    page = asyncio.run(collect(trusted, INPUT))
    assert page.html == page_payload()["html"]
    assert requests == [("/collect", f"Bearer {TOKEN}", {"url": INPUT})]
    untrusted = replace(trusted, ca_file=tls_material / "untrusted.pem")
    with pytest.raises(CollectionError) as caught:
        asyncio.run(collect(untrusted, INPUT))
    assert re.fullmatch(r"[a-z][a-z0-9_]{0,63}", caught.value.code)
    assert str(caught.value) == caught.value.code
    assert requests == [("/collect", f"Bearer {TOKEN}", {"url": INPUT})]


def _assert_clean(error):
    assert error.__context__ is None and error.__cause__ is None
    tb = error.__traceback__
    while tb is not None:
        for value in tb.tb_frame.f_locals.values():
            assert TOKEN not in repr(value) or not isinstance(value, (str, dict, bytes))
            assert TOKEN not in str(value) if isinstance(value, (str, dict)) else True
        tb = tb.tb_next


def test_translated_errors_carry_no_context_or_token_in_frames(configured_collector):
    def connect(request):
        raise httpx.ConnectError("boom", request=request)

    errors = [
        collection_error(configured_collector, connect),
        collection_error(configured_collector, lambda r: raw_response(status=401, raw=b"x")),
        collection_error(configured_collector, lambda r: raw_response(raw=b"not-json")),
        collection_error(configured_collector, lambda r: raw_response(status=503, raw=b"x")),
    ]
    for error in errors:
        _assert_clean(error)


def test_bad_ca_file_and_invalid_url_map_to_fixed_codes(configured_collector, tmp_path):
    from isolation_tests.adapters.collector import PREPARATION_CODES, CollectionError, collect

    missing = replace(configured_collector, ca_file=tmp_path / "absent.pem")
    broken = tmp_path / "broken.pem"
    broken.write_text("not a certificate", encoding="ascii")
    for config in (missing, replace(configured_collector, ca_file=broken)):
        with pytest.raises(CollectionError) as caught:
            asyncio.run(collect(config, INPUT))
        assert caught.value.code == "ca_file_unusable"
        _assert_clean(caught.value)
    bad_url = replace(configured_collector, collector_url="https://[::1/x")
    with pytest.raises(CollectionError) as caught:
        asyncio.run(collect(bad_url, INPUT, client=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: raw_response()))))
    assert caught.value.code == "collector_url_invalid"
    _assert_clean(caught.value)
    assert {"collector_not_configured", "token_missing", "token_invalid", "ca_file_unusable"} <= PREPARATION_CODES
