"""Wire contracts for controlled HTTP fixtures; all traffic stays on loopback."""

import html
import http.client
import re
import socket
from urllib.parse import parse_qs, urljoin, urlsplit

import httpx
import pytest


NETWORK_ROUTES = (
    ("NAV-04", "http"), ("NAV-04", "js"),
    ("NET-01", "img"), ("NET-01", "script"),
    ("NET-01", "iframe"), ("NET-01", "fetch"),
    ("NET-02", "action"), ("NET-02", "formaction"),
    ("NET-03", "loopback"), ("NET-03", "private"),
    ("NET-03", "link-local"), ("NET-03", "main-public"),
    ("NET-03", "isolation-public"),
    ("NET-04", "shared-ip-host"), ("NET-04", "same-host-path"),
    ("NET-06", "websocket"), ("NET-06", "worker"),
    ("NET-06", "service-worker"),
)


def test_health_is_complete_http11_response(server_base):
    response = httpx.get(server_base + "/healthz", trust_env=False)
    assert response.status_code == 200
    assert response.http_version == "HTTP/1.1"
    assert int(response.headers["content-length"]) == len(response.content)


@pytest.mark.parametrize("case_id,variant,hops", [
    ("NAV-02", "hops-1", 1), ("NAV-02", "hops-5", 5),
    ("NAV-03", "hops-6", 6),
])
def test_redirect_chain_has_real_hops_and_baseline_destination(server_base, case_id, variant, hops):
    response = httpx.get(
        f"{server_base}/v1/cases/{case_id}/{variant}",
        follow_redirects=True, trust_env=False,
    )
    assert len(response.history) == hops
    assert all(item.status_code == 302 for item in response.history)
    assert all(urlsplit(str(item.url)).netloc == urlsplit(server_base).netloc
               for item in (*response.history, response))
    assert response.status_code == 200
    assert "배송 상태" in response.text
    assert int(response.headers["content-length"]) == len(response.content)


def test_redirect_loop_repeats_two_real_routes(server_base):
    destination = server_base + "/v1/cases/NAV-03/loop"
    locations = []
    with httpx.Client(trust_env=False, follow_redirects=False) as client:
        for _ in range(6):
            response = client.get(destination)
            assert response.status_code == 302
            destination = urljoin(destination, response.headers["location"])
            assert urlsplit(destination).netloc == urlsplit(server_base).netloc
            locations.append(destination)
    assert len(set(locations)) == 2
    assert locations[0] != locations[1]
    assert locations[0::2] == [locations[0]] * 3
    assert locations[1::2] == [locations[1]] * 3


@pytest.mark.parametrize("variant", ["http", "js"])
def test_forbidden_redirect_uses_configured_receiver_and_safe_run_id(fixture_server_factory, variant):
    receiver = fixture_server_factory()
    server = fixture_server_factory(targets={"forbidden_receiver": receiver.base + "/"})
    response = httpx.get(
        f"{server.base}/v1/cases/NAV-04/{variant}",
        params={"run_id": "run-navigation", "url": "https://unconfigured.invalid/"},
        trust_env=False,
    )
    if variant == "http":
        assert response.status_code == 302
        destination = urlsplit(urljoin(str(response.url), response.headers["location"]))
        assert destination.netloc == urlsplit(receiver.base).netloc
        assert destination.path == "/v1/receive/NAV-04"
        assert parse_qs(destination.query) == {"run_id": ["run-navigation"]}
    else:
        assert response.status_code == 200
        body = html.unescape(response.text).replace("\\/", "/")
        assert receiver.base + "/v1/receive/NAV-04?run_id=run-navigation" in body
        assert re.search(r"location\s*(?:\.|\[|=)", body)
    assert "unconfigured.invalid" not in response.text


@pytest.mark.parametrize("variant,status", [
    ("403", 403), ("404", 404), ("500", 500),
    ("block-page", 200), ("captcha-page", 200),
])
def test_http_status_and_content_page_are_distinct_fixtures(server_base, variant, status):
    response = httpx.get(f"{server_base}/v1/cases/HTTP-01/{variant}", trust_env=False)
    assert response.status_code == status
    assert response.headers["content-type"].lower().startswith("text/html")
    assert int(response.headers["content-length"]) == len(response.content)
    body = response.content.decode("utf-8", errors="strict")
    assert body
    if variant == "block-page":
        assert "차단" in body
    elif variant == "captcha-page":
        assert "captcha" in body.lower() or "자동" in body


def test_wrong_mime_is_html_delivered_as_non_html(server_base):
    response = httpx.get(server_base + "/v1/cases/HTTP-02/wrong-mime", trust_env=False)
    assert response.status_code == 200
    assert not response.headers["content-type"].lower().startswith("text/html")
    assert "<html" in response.content.decode("utf-8").lower()
    assert int(response.headers["content-length"]) == len(response.content)


def test_invalid_utf8_reaches_client_as_invalid_bytes(server_base):
    response = httpx.get(server_base + "/v1/cases/HTTP-02/invalid-utf8", trust_env=False)
    assert response.status_code == 200
    with pytest.raises(UnicodeDecodeError):
        response.content.decode("utf-8", errors="strict")


def test_truncated_response_fails_protocol_instead_of_appearing_complete(server_base):
    with pytest.raises(httpx.RemoteProtocolError):
        httpx.get(server_base + "/v1/cases/HTTP-02/truncated", trust_env=False, timeout=3)


def test_attachment_is_bounded_nonexecutable_sample(server_base):
    response = httpx.get(server_base + "/v1/cases/DL-02/attachment", trust_env=False)
    assert response.status_code == 200
    disposition = response.headers["content-disposition"].lower()
    assert disposition.startswith("attachment") and "sample.apk" in disposition
    assert response.content == b"ISOLATION TEST ONLY - NON EXECUTABLE SAMPLE\n"
    assert int(response.headers["content-length"]) == len(response.content)


@pytest.mark.parametrize("path", [
    "/unregistered", "/v1/cases/UNKNOWN-01/default",
    "/v1/cases/HTTP-01/not-a-variant", "/v1/receive/UNKNOWN-01",
    "/v1/receive/NET-01/extra", "/v1/receiver-events",
])
def test_server_exposes_only_registered_paths(server_base, path):
    response = httpx.get(server_base + path, trust_env=False)
    assert response.status_code == 404


@pytest.mark.parametrize("case_id,variant", NETWORK_ROUTES)
def test_missing_network_target_fails_closed_without_breaking_health(server_base, case_id, variant):
    from isolation_tests.fixture_server import response_plan

    with pytest.raises(ValueError):
        response_plan(case_id, variant, {})
    response = httpx.get(f"{server_base}/v1/cases/{case_id}/{variant}", trust_env=False)
    assert 400 <= response.status_code < 600
    assert "location" not in response.headers
    assert httpx.get(server_base + "/healthz", trust_env=False).status_code == 200


@pytest.mark.parametrize("variant", ["img", "script", "iframe", "fetch"])
def test_network_fixture_derives_concrete_receiver_url(fixture_server_factory, variant):
    receiver = fixture_server_factory()
    server = fixture_server_factory(targets={"forbidden_receiver": receiver.base})
    response = httpx.get(
        f"{server.base}/v1/cases/NET-01/{variant}?run_id=run-network", trust_env=False,
    )
    assert response.status_code == 200
    body = html.unescape(response.text).replace("\\/", "/")
    assert receiver.base + "/v1/receive/NET-01?run_id=run-network" in body


@pytest.mark.parametrize("variant,pattern", [
    ("worker", r"new\s+Worker\(\s*(['\"])(.*?)\1"),
    ("service-worker", r"serviceWorker\s*\.\s*register\(\s*(['\"])(.*?)\1"),
])
def test_worker_scripts_are_served_same_origin_and_contain_fixed_receiver_probe(
    fixture_server_factory, variant, pattern,
):
    receiver = fixture_server_factory()
    server = fixture_server_factory(targets={"forbidden_receiver": receiver.base})
    response = httpx.get(
        f"{server.base}/v1/cases/NET-06/{variant}?run_id=run-worker", trust_env=False,
    )
    assert response.status_code == 200
    match = re.search(pattern, html.unescape(response.text))
    assert match is not None, "NET-06 must declare an actual script URL"
    script_url = urljoin(str(response.url), match.group(2))
    assert urlsplit(script_url).netloc == urlsplit(server.base).netloc
    script = httpx.get(script_url, trust_env=False)
    assert script.status_code == 200
    assert "javascript" in script.headers["content-type"].lower()
    assert receiver.base + "/v1/receive/NET-06" in script.text.replace("\\/", "/")
    assert "run-worker" in script.text or "run-worker" in script_url


@pytest.mark.parametrize("host", ["0.0.0.0", "192.0.2.17", "::"])
def test_external_bind_without_tls_is_rejected_before_binding(host):
    from isolation_tests.fixture_server import FixtureConfig, make_server

    with pytest.raises(ValueError):
        make_server(FixtureConfig(host=host))


@pytest.mark.parametrize("present", ["tls_cert", "tls_key"])
def test_partial_tls_configuration_is_rejected(tmp_path, present):
    from isolation_tests.fixture_server import FixtureConfig, make_server

    placeholder = tmp_path / "synthetic.pem"
    placeholder.write_text("synthetic incomplete TLS fixture", encoding="utf-8")
    with pytest.raises(ValueError):
        make_server(FixtureConfig(**{present: placeholder}))


def test_post_is_rejected_without_waiting_for_declared_body_and_connection_closes(fixture_server):
    # Sending only headers catches a handler that tries to read the POST body.
    address = ("127.0.0.1", fixture_server.server.server_port)
    with socket.create_connection(address, timeout=2) as connection:
        connection.sendall(
            b"POST /v1/receive/NET-02?run_id=run-post HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\nContent-Length: 1048576\r\n\r\n"
        )
        response = http.client.HTTPResponse(connection)
        response.begin()
        assert response.status == 405
        assert response.getheader("Connection", "").lower() == "close"
        response.read()
        assert connection.recv(1) == b""


def test_static_mirror_serves_exact_builder_bytes(fixture_server_factory, static_mirror_root):
    server = fixture_server_factory(static_root=static_mirror_root)
    for path in ("v1/cases/col-01/index.html", "v1/files/sample.apk"):
        response = httpx.get(f"{server.base}/v1/static/{path}", trust_env=False)
        assert response.status_code == 200
        assert response.content == (static_mirror_root / path).read_bytes()
        assert int(response.headers["content-length"]) == len(response.content)


def test_static_mirror_cannot_publish_arbitrary_files_in_root(fixture_server_factory, static_mirror_root):
    secret = b"synthetic local-only file must not be served"
    (static_mirror_root / "private.pem").write_bytes(secret)
    server = fixture_server_factory(static_root=static_mirror_root)
    response = httpx.get(server.base + "/v1/static/private.pem", trust_env=False)
    assert response.status_code in {400, 403, 404}
    assert secret not in response.content


@pytest.mark.parametrize("path", [
    "%2e%2e/outside.txt", "%2e%2e%2foutside.txt", "%252e%252e%252foutside.txt",
    "v1/%2e%2e/%2e%2e/%2e%2e/outside.txt", "..%5coutside.txt",
])
def test_encoded_static_traversal_never_discloses_outside_file(
    fixture_server_factory, static_mirror_root, path,
):
    secret = b"synthetic traversal sentinel"
    (static_mirror_root.parent / "outside.txt").write_bytes(secret)
    server = fixture_server_factory(static_root=static_mirror_root)
    response = httpx.get(f"{server.base}/v1/static/{path}", trust_env=False)
    assert response.status_code in {400, 403, 404}
    assert secret not in response.content


def test_static_symlink_escape_is_rejected(fixture_server_factory, static_mirror_root):
    secret = b"synthetic symlink sentinel"
    outside = static_mirror_root.parent / "outside.html"
    outside.write_bytes(secret)
    path = static_mirror_root / "v1/cases/col-01/index.html"
    path.unlink()
    try:
        path.symlink_to(outside)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"Windows symlink privilege unavailable: {error}")
    server = fixture_server_factory(static_root=static_mirror_root)
    response = httpx.get(server.base + "/v1/static/v1/cases/col-01/index.html", trust_env=False)
    assert response.status_code in {400, 403, 404}
    assert secret not in response.content
