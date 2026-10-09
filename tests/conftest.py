"""Synthetic fixtures shared by the manifest and CLI contract tests."""

import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools" / "isolation-tests"))


@pytest.fixture
def case_data():
    # Every documented CaseSpec field is present, independent of product code.
    return {
        "id": "COL-01",
        "group": "collection",
        "title": "수집 기준",
        "description": "기본 수집 합성 표본",
        "execution_kind": "page",
        "target_key": "pages",
        "relative_path": "v1/cases/col-01/index.html",
        "variants": ["default"],
        "required_capabilities": ["collector"],
        "message": "",
        "expected_observations": {},
        "expected_analysis": {},
        "required_evidence": ["collection"],
        "risk_level": "basic",
        "max_requests": 1,
        "recovery_case": None,
    }


@pytest.fixture
def write_manifest(tmp_path):
    def write(payload):
        path = tmp_path / "cases.json"
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return path

    return write


def pytest_configure(config):
    config.addinivalue_line("markers", "browser: optional local Chromium page tests")
    config.addinivalue_line("markers", "timing: explicit real-time fixture checks")


@pytest.fixture
def browser(request):
    # Check before importing Playwright or starting any browser process.
    if request.node.get_closest_marker("browser") is None:
        pytest.fail("browser fixture requires @pytest.mark.browser")
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        instance = playwright.chromium.launch()
        yield instance
        instance.close()


@pytest.fixture(scope="session")
def site_url(tmp_path_factory):
    from functools import partial
    from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    from isolation_tests.build_pages import build_site
    from isolation_tests.manifest import load_cases

    root = tmp_path_factory.mktemp("browser-site")
    # Serving from this non-root prefix exposes accidentally absolute links.
    prefix = "synthetic-project-prefix"
    build_site(
        load_cases(REPO_ROOT / "tools" / "isolation-tests" / "cases.json"),
        root / prefix,
        commit_sha="0123456789abcdef0123456789abcdef01234567",
    )

    class QuietHandler(SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(
        ("127.0.0.1", 0), partial(QuietHandler, directory=str(root))
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/{prefix}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture
def fixture_server_factory(tmp_path):
    """Start real fixture servers and reclaim every listener and serving thread."""
    from threading import Thread
    from types import SimpleNamespace

    from isolation_tests.fixture_server import FixtureConfig, make_server

    instances = []

    def start(*, targets=None, static_root=None, log_path=None):
        log_path = log_path or tmp_path / f"receiver-{len(instances)}.jsonl"
        config = FixtureConfig(
            host="127.0.0.1", port=0, targets=dict(targets or {}),
            static_root=static_root, log_path=log_path,
        )
        server = make_server(config)
        thread = Thread(target=server.serve_forever, daemon=True)
        instance = SimpleNamespace(
            server=server, thread=thread, log_path=log_path,
            base=f"http://127.0.0.1:{server.server_port}",
        )
        # A controlled startup value; never trust the incoming Host header.
        config.targets.setdefault("http_fixture", instance.base)
        instances.append(instance)
        thread.start()
        return instance

    yield start
    for instance in reversed(instances):
        instance.server.shutdown()
        instance.server.server_close()
        instance.thread.join(timeout=5)
        assert not instance.thread.is_alive(), "fixture serving thread leaked"
        assert instance.server.socket.fileno() == -1, "fixture listener leaked"


@pytest.fixture
def fixture_server(fixture_server_factory):
    return fixture_server_factory()


@pytest.fixture
def server_base(fixture_server):
    return fixture_server.base


@pytest.fixture
def receiver_log(fixture_server):
    return fixture_server.log_path


@pytest.fixture
def static_mirror_root(tmp_path):
    from isolation_tests.build_pages import build_site
    from isolation_tests.manifest import load_cases

    root = tmp_path / "static-mirror"
    build_site(
        load_cases(REPO_ROOT / "tools" / "isolation-tests" / "cases.json"),
        root,
        commit_sha="0123456789abcdef0123456789abcdef01234567",
    )
    return root


class SlotEvents:
    """Private event injection; there is no HTTP administration endpoint."""

    def __init__(self):
        from threading import Condition

        self.condition = Condition()
        self.count = 0
        self.peak = 0

    def changed(self, count):
        with self.condition:
            self.count = count
            self.peak = max(self.peak, count)
            self.condition.notify_all()

    def wait_for(self, count, timeout=3):
        with self.condition:
            assert self.condition.wait_for(lambda: self.count == count, timeout), (
                f"expected {count} active slots, observed {self.count}"
            )


@pytest.fixture
def running_server():
    from contextlib import contextmanager
    from threading import Thread

    from isolation_tests.fixture_server import make_server

    class ServerURL(str):
        pass

    @contextmanager
    def run(config, **hooks):
        slots = SlotEvents()
        server = make_server(config, on_slot_change=slots.changed, **hooks)
        base = ServerURL(f"http://127.0.0.1:{server.server_port}")
        base.server = server
        base.slots = slots
        config.targets.setdefault("http_fixture", str(base))
        _HELD_SERVERS[str(base)] = base
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield base
        finally:
            _HELD_SERVERS.pop(str(base), None)
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            assert not thread.is_alive(), "fixture serving thread leaked"
            assert server.socket.fileno() == -1, "fixture listener leaked"

    return run


_HELD_SERVERS = {}


@pytest.fixture
def hold_request():
    from contextlib import contextmanager
    import socket
    from urllib.parse import urlsplit

    @contextmanager
    def hold(url):
        parts = urlsplit(url)
        server = _HELD_SERVERS[f"{parts.scheme}://{parts.netloc}"]
        with server.slots.condition:
            expected = server.slots.count + 1
        connection = socket.create_connection((parts.hostname, parts.port), timeout=2)
        try:
            path = parts.path + ("?" + parts.query if parts.query else "")
            connection.sendall(
                f"GET {path} HTTP/1.1\r\nHost: {parts.netloc}\r\nConnection: close\r\n\r\n"
                .encode("ascii")
            )
            server.slots.wait_for(expected)
            yield connection
        finally:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()

    return hold


def pytest_addoption(parser):
    parser.addoption("--run-timing", action="store_true", help="run real 15/20-second fixtures")


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--run-timing"):
        skip = pytest.mark.skip(reason="real-time fixtures require --run-timing")
        for item in items:
            if item.get_closest_marker("timing"):
                item.add_marker(skip)


@pytest.fixture
def configured_collector(monkeypatch):
    """Use the documented configuration with an isolated synthetic credential."""
    from dataclasses import replace

    from isolation_tests.config import load_config

    monkeypatch.setenv("TEST_ONLY_TOKEN", "synthetic-test-token")
    return replace(
        load_config(REPO_ROOT / "tools" / "isolation-tests" / "config.example.json"),
        collector_url="https://collector.example.invalid/collect",
        token_env="TEST_ONLY_TOKEN",
    )


@pytest.fixture
def backend_case():
    from isolation_tests.manifest import load_cases

    cases = load_cases(REPO_ROOT / "tools" / "isolation-tests" / "cases.json")
    return next(case for case in cases if case.id == "INT-03")


@pytest.fixture
def write_backend_contract(tmp_path):
    """Write a synthetic contract derived from the documented example."""
    def write(**overrides):
        example = json.loads(
            (REPO_ROOT / "tools" / "isolation-tests" / "backend-contract.example.json")
            .read_text(encoding="utf-8"))
        path = tmp_path / "backend-contract.json"
        path.write_text(json.dumps(example | overrides), encoding="utf-8")
        return path

    return write


@pytest.fixture
def configured_backend(write_backend_contract):
    """Documented configuration pointing at a synthetic backend; result fields stay null."""
    from dataclasses import replace

    from isolation_tests.config import load_config

    contract = write_backend_contract(submit_url="https://backend.example.invalid/skill")
    return replace(
        load_config(REPO_ROOT / "tools" / "isolation-tests" / "config.example.json"),
        backend_contract=contract,
    )
