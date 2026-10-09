"""Fixture server bounds are independent of any operational collector limits."""

from contextlib import ExitStack
from dataclasses import replace
import gzip
import socket
from threading import Event, Lock
import time

import httpx
import pytest


MAX_BODY = 8 * 1024 * 1024


class SteppedClock:
    def __init__(self, overshoot=0):
        self.value = 1000.0
        self.sleeps = []
        self.overshoot = overshoot
        self.lock = Lock()

    def now(self):
        with self.lock:
            return self.value

    def sleep(self, seconds):
        assert seconds >= 0
        with self.lock:
            self.sleeps.append(seconds)
            self.value += seconds + self.overshoot


class PausedClock(SteppedClock):
    def __init__(self):
        super().__init__()
        self.release = Event()

    def sleep(self, seconds):
        assert self.release.wait(timeout=5), "test did not release paused fixture clock"
        super().sleep(seconds)


@pytest.mark.parametrize("size", [0, 1, MAX_BODY])
def test_bounded_chunks_preserve_every_byte(size):
    from isolation_tests.fixture_server import bounded_chunks

    body = b"a" * size
    chunks = list(bounded_chunks(body, 4096))
    assert b"".join(chunks) == body
    assert all(0 < len(chunk) <= 4096 for chunk in chunks)


@pytest.mark.parametrize("size,chunk_size", [
    (MAX_BODY + 1, 4096), (1, 0), (1, -1), (1, None),
    (1, float("inf")), (1, 1.5), (1, True),
])
def test_bounded_chunks_reject_unbounded_or_invalid_requests(size, chunk_size):
    from isolation_tests.fixture_server import bounded_chunks

    with pytest.raises(ValueError):
        list(bounded_chunks(b"x" * size, chunk_size))


@pytest.mark.parametrize("max_active", [0, -1, 5, None, float("inf"), 1.5, True])
def test_server_cannot_be_configured_without_four_request_ceiling(max_active):
    from isolation_tests.fixture_server import FixtureConfig, make_server

    with pytest.raises(ValueError):
        server = make_server(FixtureConfig(max_active=max_active))
        server.server_close()


@pytest.mark.parametrize("field,value", [
    ("start_delay_s", -1), ("start_delay_s", 21),
    ("start_delay_s", float("inf")), ("start_delay_s", float("nan")),
    ("chunk_interval_s", -1), ("chunk_interval_s", float("inf")),
    ("max_duration_s", 0), ("max_duration_s", -1),
    ("max_duration_s", 21), ("max_duration_s", float("inf")),
    ("chunk_size", 0), ("chunk_size", -1),
])
def test_response_plan_rejects_unbounded_timing_and_chunk_parameters(field, value):
    from isolation_tests.fixture_server import ResponsePlan

    with pytest.raises(ValueError):
        replace(ResponsePlan(200, (), b"x"), **{field: value})


@pytest.mark.parametrize("compressed", [False, True])
def test_response_plan_rejects_oversized_body_even_when_gzip_is_small(compressed):
    from isolation_tests.fixture_server import ResponsePlan

    body = b"x" * (MAX_BODY + 1)
    headers = ()
    if compressed:
        body = gzip.compress(body)
        headers = (("Content-Encoding", "gzip"),)
    with pytest.raises(ValueError):
        ResponsePlan(200, headers, body)


@pytest.mark.parametrize("variant", ["large", "length-small", "length-large", "gzip"])
def test_size_plans_never_exceed_compressed_or_decompressed_eight_mib(variant):
    from isolation_tests.fixture_server import response_plan

    plan = response_plan("LIM-03", variant, {})
    assert 0 < len(plan.body) <= MAX_BODY
    headers = {key.lower(): value for key, value in plan.headers}
    if variant == "gzip":
        assert headers.get("content-encoding") == "gzip"
        body = gzip.decompress(plan.body)
        assert 131072 < len(body) <= MAX_BODY
        assert len(plan.body) < len(body)
    else:
        assert len(plan.body) > 131072
    if variant == "length-small":
        assert 0 <= int(headers["content-length"]) < len(plan.body)
    elif variant == "length-large":
        assert int(headers["content-length"]) > len(plan.body)


def test_gzip_wire_response_is_bounded(server_base):
    with httpx.stream("GET", server_base + "/v1/cases/LIM-03/gzip", trust_env=False) as response:
        compressed = b"".join(response.iter_raw())
        assert response.status_code == 200
        assert response.headers["content-encoding"] == "gzip"
        assert int(response.headers["content-length"]) == len(compressed)
    assert len(compressed) <= MAX_BODY
    assert 131072 < len(gzip.decompress(compressed)) <= MAX_BODY


@pytest.mark.parametrize("variant", ["length-small", "length-large"])
def test_declared_length_mismatch_reaches_actual_wire(server_base, variant):
    from urllib.parse import urlsplit

    parts = urlsplit(server_base)
    with socket.create_connection((parts.hostname, parts.port), timeout=3) as connection:
        connection.sendall(
            f"GET /v1/cases/LIM-03/{variant} HTTP/1.1\r\nHost: {parts.netloc}\r\nConnection: close\r\n\r\n"
            .encode("ascii")
        )
        received = bytearray()
        while chunk := connection.recv(65536):
            received.extend(chunk)
    head, body = bytes(received).split(b"\r\n\r\n", 1)
    headers = dict(line.decode("ascii").split(": ", 1) for line in head.split(b"\r\n")[1:])
    declared = int(next(value for key, value in headers.items() if key.lower() == "content-length"))
    assert 0 < len(body) <= MAX_BODY
    assert (declared < len(body)) if variant == "length-small" else (declared > len(body))


def test_delay_waits_fifteen_seconds_on_injected_monotonic_clock(running_server):
    from isolation_tests.fixture_server import FixtureConfig

    clock = SteppedClock()
    with running_server(FixtureConfig(), now=clock.now, sleep=clock.sleep) as base:
        response = httpx.get(base + "/v1/cases/LIM-01/delay-15s", trust_env=False, timeout=2)
        assert response.status_code == 200
        assert 15 <= sum(clock.sleeps) <= 20
        base.slots.wait_for(0)


def test_slow_stream_has_one_second_intervals_and_twenty_second_total(running_server):
    from isolation_tests.fixture_server import FixtureConfig, response_plan

    plan = response_plan("LIM-02", "slow-stream", {})
    assert plan.chunk_interval_s == 1
    assert plan.max_duration_s == 20
    clock = SteppedClock()
    with running_server(FixtureConfig(), now=clock.now, sleep=clock.sleep) as base:
        with httpx.stream("GET", base + "/v1/cases/LIM-02/slow-stream", trust_env=False, timeout=2) as response:
            try:
                body = b"".join(response.iter_bytes())
                assert body
            except httpx.RemoteProtocolError:
                pass  # A deadline cut-off may intentionally close an incomplete body.
        assert len(clock.sleeps) >= 2, "exercise an actual spaced stream"
        assert all(0 < delay <= 1 for delay in clock.sleeps)
        assert sum(clock.sleeps) <= 20
        base.slots.wait_for(0)


def test_elapsed_deadline_is_rechecked_after_sleep_before_sending(running_server):
    from isolation_tests.fixture_server import FixtureConfig

    clock = SteppedClock(overshoot=21)
    with running_server(FixtureConfig(), now=clock.now, sleep=clock.sleep) as base:
        try:
            response = httpx.get(base + "/v1/cases/LIM-01/delay-15s", trust_env=False, timeout=2)
        except httpx.RemoteProtocolError:
            response = None
        assert response is None or not response.content or response.status_code >= 400
        assert len(clock.sleeps) == 1
        base.slots.wait_for(0)
        assert httpx.get(base + "/healthz", trust_env=False, timeout=1).status_code == 200


def test_slow_stream_stops_writing_after_monotonic_deadline(running_server):
    from isolation_tests.fixture_server import FixtureConfig, response_plan
    from urllib.parse import urlsplit

    clock = SteppedClock(overshoot=21)
    plan = response_plan("LIM-02", "slow-stream", {})
    with running_server(FixtureConfig(), now=clock.now, sleep=clock.sleep) as base:
        parts = urlsplit(base)
        with socket.create_connection((parts.hostname, parts.port), timeout=2) as connection:
            connection.sendall(
                f"GET /v1/cases/LIM-02/slow-stream HTTP/1.1\r\nHost: {parts.netloc}\r\nConnection: close\r\n\r\n"
                .encode("ascii")
            )
            received = bytearray()
            while chunk := connection.recv(65536):
                received.extend(chunk)
        _, body = bytes(received).split(b"\r\n\r\n", 1)
        assert len(body) <= plan.chunk_size, "no next chunk may be sent after sleep overruns"
        assert len(clock.sleeps) == 1
        base.slots.wait_for(0)
        assert httpx.get(base + "/healthz", trust_env=False, timeout=1).status_code == 200


def test_above_four_active_is_rejected_before_creating_a_handler_thread(
    running_server, hold_request, monkeypatch,
):
    from threading import Thread
    from isolation_tests.fixture_server import FixtureConfig

    clock = PausedClock()
    with running_server(FixtureConfig(max_active=4), now=clock.now, sleep=clock.sleep) as base:
        try:
            with ExitStack() as stack:
                for _ in range(4):
                    stack.enter_context(hold_request(base + "/v1/cases/LIM-01/delay-15s"))
                base.slots.wait_for(4)
                starts = []
                original = Thread.start

                def record_start(thread):
                    starts.append(thread)
                    return original(thread)

                monkeypatch.setattr(Thread, "start", record_start)
                response = httpx.get(base + "/healthz", trust_env=False, timeout=1)
                assert response.status_code == 503
                assert starts == [], "rejection must occur before making a request thread"
                assert base.slots.peak == 4
        finally:
            clock.release.set()
        base.slots.wait_for(0)
        assert httpx.get(base + "/healthz", trust_env=False, timeout=1).status_code == 200


def test_client_disconnect_returns_slot_and_next_health_succeeds(running_server, hold_request):
    from isolation_tests.fixture_server import FixtureConfig

    clock = PausedClock()
    with running_server(FixtureConfig(max_active=1), now=clock.now, sleep=clock.sleep) as base:
        try:
            with hold_request(base + "/v1/cases/LIM-01/delay-15s"):
                assert httpx.get(base + "/healthz", trust_env=False, timeout=1).status_code == 503
        finally:
            clock.release.set()
        base.slots.wait_for(0)
        assert httpx.get(base + "/healthz", trust_env=False, timeout=1).status_code == 200


def test_handler_error_always_returns_acquired_slot(running_server, monkeypatch):
    from isolation_tests import fixture_server

    original = fixture_server.response_plan

    def fail_one(case_id, variant, targets):
        if case_id == "HTTP-01":
            raise RuntimeError("synthetic handler failure")
        return original(case_id, variant, targets)

    monkeypatch.setattr(fixture_server, "response_plan", fail_one)
    with running_server(fixture_server.FixtureConfig(max_active=1)) as base:
        try:
            response = httpx.get(base + "/v1/cases/HTTP-01/500", trust_env=False, timeout=1)
            assert response.status_code >= 400
        except httpx.RemoteProtocolError:
            pass
        base.slots.wait_for(0)
        assert httpx.get(base + "/healthz", trust_env=False, timeout=1).status_code == 200


@pytest.mark.timing
def test_real_delay_fixture_returns_between_fifteen_and_twenty_seconds(server_base):
    started = time.monotonic()
    response = httpx.get(server_base + "/v1/cases/LIM-01/delay-15s", trust_env=False, timeout=21)
    assert response.status_code == 200
    assert 15 <= time.monotonic() - started <= 21  # local scheduling allowance


@pytest.mark.timing
def test_real_slow_stream_stops_within_twenty_seconds(server_base):
    started = time.monotonic()
    chunks = 0
    with httpx.stream("GET", server_base + "/v1/cases/LIM-02/slow-stream", trust_env=False, timeout=21) as response:
        assert response.status_code == 200
        try:
            for chunk in response.iter_raw():
                assert chunk
                chunks += 1
        except httpx.RemoteProtocolError:
            pass
    assert chunks >= 2
    assert 1 <= time.monotonic() - started <= 21


# --- fix round 1: lifetime, one slot per request, unavailable calibration -----

def _raw_get(base, path, extra=b""):
    from urllib.parse import urlsplit

    parts = urlsplit(base)
    connection = socket.create_connection((parts.hostname, parts.port), timeout=3)
    connection.sendall(
        f"GET {path} HTTP/1.1\r\nHost: {parts.netloc}\r\n".encode("ascii") + extra + b"\r\n"
    )
    return connection


def test_keep_alive_is_refused_so_one_slot_is_one_request(running_server):
    from isolation_tests.fixture_server import FixtureConfig

    with running_server(FixtureConfig(max_active=1)) as base:
        connection = _raw_get(base, "/healthz")  # HTTP/1.1 default would be keep-alive
        try:
            received = bytearray()
            while chunk := connection.recv(65536):
                received.extend(chunk)  # EOF proves the server ended the connection
            assert b"connection: close" in bytes(received).lower()
            base.slots.wait_for(0)  # the client socket is still open here
            assert httpx.get(base + "/healthz", trust_env=False, timeout=1).status_code == 200
        finally:
            connection.close()


def test_trickled_request_cannot_hold_a_slot_past_the_read_budget(running_server, monkeypatch):
    from isolation_tests import fixture_server

    monkeypatch.setattr(fixture_server._Handler, "read_budget_s", 0.5)
    with running_server(fixture_server.FixtureConfig(max_active=1)) as base:
        from urllib.parse import urlsplit

        parts = urlsplit(base)
        with socket.create_connection((parts.hostname, parts.port), timeout=3) as connection:
            connection.sendall(b"GET /heal")  # never finished
            base.slots.wait_for(1)
            base.slots.wait_for(0, timeout=4)
        assert httpx.get(base + "/healthz", trust_env=False, timeout=1).status_code == 200


def test_non_reading_client_cannot_stretch_the_response_lifetime(running_server, monkeypatch):
    from isolation_tests import fixture_server
    from urllib.parse import urlsplit

    plan = fixture_server.ResponsePlan(
        200, (("Content-Type", "text/plain"),), b"x" * MAX_BODY,
        chunk_size=65536, max_duration_s=1,
    )
    monkeypatch.setitem(fixture_server._REGISTRY, ("LIM-03", "large"), lambda t, r, h: plan)
    with running_server(fixture_server.FixtureConfig(max_active=1)) as base:
        parts = urlsplit(base)
        connection = socket.socket()
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        connection.settimeout(3)
        connection.connect((parts.hostname, parts.port))
        try:
            started = time.monotonic()
            connection.sendall(
                f"GET /v1/cases/LIM-03/large HTTP/1.1\r\nHost: {parts.netloc}\r\n\r\n".encode("ascii"))
            base.slots.wait_for(0, timeout=5)  # the handler's own send timeout is 10 s
            elapsed = time.monotonic() - started
        finally:
            connection.close()
        assert 0.8 <= elapsed <= 4, f"blocked send must end at the 1 s deadline, took {elapsed:.2f}s"
        assert httpx.get(base + "/healthz", trust_env=False, timeout=1).status_code == 200


def test_uncalibrated_result_boundary_fails_explicitly(running_server, monkeypatch):
    import sys
    from isolation_tests import fixtures, fixture_server

    monkeypatch.setitem(sys.modules, "ai.page", None)  # import raises ImportError
    monkeypatch.setattr(fixtures, "_CALIBRATED", {})
    with pytest.raises(ValueError):
        fixtures.boundary_html("result", 262144)
    with running_server(fixture_server.FixtureConfig()) as base:
        for offset in (-1, 0, 1):
            response = httpx.get(f"{base}/v1/cases/LIM-04/result?offset={offset}", trust_env=False)
            assert response.status_code == 503 and response.content == b""
        assert httpx.get(f"{base}/v1/cases/LIM-04/bytes?offset=1", trust_env=False).status_code == 200


def test_boolean_offset_is_rejected():
    from isolation_tests.fixture_server import RequestRejected, response_plan

    with pytest.raises(RequestRejected):
        response_plan("LIM-04", "bytes", {}, offset=True)
