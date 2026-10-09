"""Synthetic receiver evidence is bounded, correlated, and free of request secrets."""

import json
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest


EVENT_FIELDS = {"at", "case_id", "run_id", "method", "path", "bytes_sent"}


def _events(path, *, count=1):
    # The HTTP body may finish just before the handler appends its event.
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        if path.exists():
            lines = path.read_text(encoding="utf-8").splitlines()
            if len(lines) >= count:
                return [json.loads(line) for line in lines]
        time.sleep(0.01)
    pytest.fail("receiver did not append expected complete JSONL events")


def _event(**changes):
    event = {
        "at": "2026-10-10T01:02:03+00:00", "case_id": "NET-01",
        "run_id": "run-safe", "method": "GET", "path": "/v1/receive/NET-01",
        "bytes_sent": 2,
    }
    event.update(changes)
    return event


def _write_jsonl(path, events):
    path.write_text(
        "".join(json.dumps(event, ensure_ascii=False) + "\n" for event in events),
        encoding="utf-8",
    )


def test_receiver_logs_only_allowlisted_fields_and_actual_bytes(server_base, receiver_log):
    response = httpx.get(
        server_base + "/v1/receive/NET-01?run_id=run-test&private=test-only",
        headers={"Authorization": "Bearer synthetic-secret", "Cookie": "synthetic-cookie",
                 "Referer": "https://referer.invalid/synthetic-private"},
        trust_env=False,
    )
    assert response.status_code == 200
    event, = _events(receiver_log)
    assert set(event) == EVENT_FIELDS
    assert event["case_id"] == "NET-01"
    assert event["run_id"] == "run-test"
    assert event["method"] == "GET"
    assert event["path"] == "/v1/receive/NET-01"
    assert event["bytes_sent"] == len(response.content)
    assert isinstance(event["at"], str) and event["at"]
    data = receiver_log.read_text(encoding="utf-8")
    for sensitive in ("synthetic-secret", "synthetic-cookie", "test-only", "synthetic-private"):
        assert sensitive not in data


def test_headers_body_and_unknown_query_never_reach_access_logs(server_base, receiver_log, capfd):
    synthetic_secret = "synthetic-do-not-log-9381"
    response = httpx.post(
        server_base + "/v1/receive/NET-02?run_id=run-post&private=" + synthetic_secret,
        headers={"Authorization": "Bearer " + synthetic_secret, "Cookie": synthetic_secret},
        content=synthetic_secret.encode(), trust_env=False,
    )
    assert response.status_code == 405
    assert response.headers["connection"].lower() == "close"
    # A subsequent completed GET gives rejected request handling time to finish.
    httpx.get(server_base + "/v1/receive/NET-01?run_id=run-after-post", trust_env=False)
    _events(receiver_log)
    output = capfd.readouterr()
    assert synthetic_secret not in output.out + output.err
    assert synthetic_secret not in receiver_log.read_text(encoding="utf-8")


@pytest.mark.parametrize("run_id", [
    "bad%0Arun", "bad%0Drun", "bad%2Frun", "bad%3Ftoken%3Dsynthetic",
    pytest.param("x" * 4096, id="oversized"),
])
def test_unsafe_run_id_cannot_be_stored_verbatim(server_base, receiver_log, run_id):
    from urllib.parse import unquote

    response = httpx.get(server_base + "/v1/receive/NET-01?run_id=" + run_id, trust_env=False)
    assert response.status_code == 200 or 400 <= response.status_code < 500
    httpx.get(server_base + "/v1/receive/NET-01?run_id=run-control", trust_env=False)
    events = _events(receiver_log)
    assert all(set(event) == EVENT_FIELDS for event in events)
    assert all(event["run_id"] != unquote(run_id) for event in events)
    assert all(len(event["run_id"]) < 4096 for event in events)


def test_jsonl_writer_is_complete_under_concurrent_appends(tmp_path):
    from isolation_tests.receiver import read_receiver_events, write_receiver_event

    path = tmp_path / "receiver.jsonl"

    def append(index):
        write_receiver_event(
            path, case_id="NET-01", run_id=f"run-{index}", method="GET",
            fixed_path="/v1/receive/NET-01", bytes_sent=index,
            at="2026-10-10T01:02:03+00:00",
        )

    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(append, range(100)))
    events = _events(path, count=100)
    assert len(events) == 100
    assert {event["run_id"] for event in events} == {f"run-{index}" for index in range(100)}
    assert all(set(event) == EVENT_FIELDS for event in events)
    assert read_receiver_events(path, "run-37") == (_event(run_id="run-37", bytes_sent=37),)


def test_reader_returns_only_exact_run_matches_without_mutating_input(tmp_path):
    from isolation_tests.receiver import read_receiver_events

    path = tmp_path / "receiver.jsonl"
    matching = _event()
    _write_jsonl(path, [_event(run_id="run-safe-extra"), matching, _event(run_id="run-other")])
    before = path.read_bytes()
    assert read_receiver_events(path, "run-safe") == (matching,)
    assert read_receiver_events(path, "run-absent") == ()
    assert path.read_bytes() == before


@pytest.mark.parametrize("changes", [
    {"Authorization": "Bearer synthetic-private"},
    {"path": "/v1/receive/NET-01?token=synthetic-private"},
    {"path": "/v1/receive/NET-02"},
    {"case_id": "UNKNOWN-01"}, {"run_id": "unsafe\nrun"},
    {"bytes_sent": -1}, {"bytes_sent": True}, {"bytes_sent": "2"},
    {"method": "GET\nsynthetic-private"}, {"at": None},
])
def test_reader_rejects_unsafe_or_untyped_event_fields(tmp_path, changes):
    from isolation_tests.receiver import read_receiver_events

    path = tmp_path / "receiver.jsonl"
    _write_jsonl(path, [_event(**changes)])
    with pytest.raises(ValueError):
        read_receiver_events(path, "run-safe")


@pytest.mark.parametrize("payload", [
    b'{"run_id":', b'[]\n', b'null\n', b'{}\n', b'\xff\n',
    b'{"at":"2026-10-10T01:02:03+00:00","case_id":"NET-01",'
    b'"run_id":"run-safe","run_id":"run-other","method":"GET",'
    b'"path":"/v1/receive/NET-01","bytes_sent":2}\n',
])
def test_reader_rejects_malformed_jsonl_and_duplicate_keys(tmp_path, payload):
    from isolation_tests.receiver import read_receiver_events

    path = tmp_path / "receiver.jsonl"
    path.write_bytes(payload)
    with pytest.raises(ValueError):
        read_receiver_events(path, "run-safe")


def test_reader_rejects_input_larger_than_one_mib(tmp_path):
    from isolation_tests.receiver import read_receiver_events

    path = tmp_path / "receiver.jsonl"
    line = (json.dumps(_event()) + "\n").encode()
    path.write_bytes(line * (1048576 // len(line) + 1))
    with pytest.raises(ValueError):
        read_receiver_events(path, "run-safe")


def test_reader_rejects_directory(tmp_path):
    from isolation_tests.receiver import read_receiver_events

    with pytest.raises((ValueError, OSError)):
        read_receiver_events(tmp_path, "run-safe")


def test_reader_does_not_follow_symlink(tmp_path):
    destination = tmp_path / "outside.jsonl"
    _write_jsonl(destination, [_event()])
    path = tmp_path / "receiver.jsonl"
    try:
        path.symlink_to(destination)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"Windows symlink privilege unavailable: {error}")
    from isolation_tests.receiver import read_receiver_events

    with pytest.raises(ValueError):
        read_receiver_events(path, "run-safe")


@pytest.mark.parametrize("run_id", [
    "", "run\nunsafe", "run/token", pytest.param("x" * 4096, id="oversized"),
])
def test_reader_rejects_unsafe_correlation_id(tmp_path, run_id):
    from isolation_tests.receiver import read_receiver_events

    path = tmp_path / "receiver.jsonl"
    _write_jsonl(path, [_event()])
    with pytest.raises(ValueError):
        read_receiver_events(path, run_id)


def _write(path, run_id="run-safe", **changes):
    from isolation_tests.receiver import write_receiver_event

    values = dict(case_id="NET-01", run_id=run_id, method="GET",
                  fixed_path="/v1/receive/NET-01", bytes_sent=2,
                  at="2026-10-10T01:02:03+00:00")
    values.update(changes)
    write_receiver_event(path, **values)


def test_writer_refuses_events_past_the_reader_limit(tmp_path, monkeypatch):
    from isolation_tests import receiver

    path = tmp_path / "receiver.jsonl"
    line_size = len(json.dumps(_event()) + "\n")
    monkeypatch.setattr(receiver, "MAX_LOG_BYTES", line_size * 3 + 10)
    for _ in range(3):
        _write(path)
    before = path.read_bytes()
    with pytest.raises(receiver.ReceiverLogFull):
        _write(path)
    assert path.read_bytes() == before
    assert len(receiver.read_receiver_events(path, "run-safe")) == 3


def test_real_cap_leaves_log_readable_after_flood(tmp_path, monkeypatch):
    from isolation_tests import receiver

    path = tmp_path / "receiver.jsonl"
    monkeypatch.setattr(receiver, "MAX_LOG_BYTES", 2048)
    refused = 0
    for index in range(100):
        try:
            _write(path, run_id=f"flood-{index}")
        except receiver.ReceiverLogFull:
            refused += 1
    assert refused > 0 and path.stat().st_size <= 2048
    assert receiver.read_receiver_events(path, "flood-0")


def test_torn_tail_does_not_swallow_the_next_event(tmp_path):
    path = tmp_path / "receiver.jsonl"
    path.write_bytes(b'{"run_id":"torn')
    _write(path)
    lines = path.read_bytes().split(b"\n")
    assert json.loads(lines[1])["run_id"] == "run-safe"


def test_reader_rejects_naive_timestamp(tmp_path):
    from isolation_tests.receiver import read_receiver_events

    path = tmp_path / "receiver.jsonl"
    _write_jsonl(path, [_event(at="2026-10-10T01:02:03")])
    with pytest.raises(ValueError):
        read_receiver_events(path, "run-safe")


def test_full_log_never_answers_success(fixture_server, monkeypatch, capfd):
    from isolation_tests import receiver

    monkeypatch.setattr(receiver, "MAX_LOG_BYTES", 10)
    response = httpx.get(fixture_server.base + "/v1/receive/NET-01?run_id=run-full", trust_env=False)
    assert response.status_code == 503
    assert "ReceiverLogFull" in capfd.readouterr().err


def test_unwritable_log_never_answers_success(fixture_server_factory, tmp_path, capfd):
    # A directory as the log path makes every append fail.
    server = fixture_server_factory(log_path=tmp_path)
    response = httpx.get(server.base + "/v1/receive/NET-01?run_id=run-bad", trust_env=False)
    assert response.status_code == 503
    assert "route=receiver-log" in capfd.readouterr().err


def test_unexpected_handler_error_is_visible_without_request_data(
    fixture_server, monkeypatch, capfd,
):
    from isolation_tests import fixture_server as module

    def broken(*args):
        raise RuntimeError("synthetic-secret-message")

    monkeypatch.setitem(module._REGISTRY, ("HTTP-01", "403"), broken)
    response = httpx.get(fixture_server.base + "/v1/cases/HTTP-01/403?x=synthetic-query", trust_env=False)
    assert response.status_code == 500
    err = capfd.readouterr().err
    assert "RuntimeError" in err and "route=route" in err
    assert "synthetic-secret-message" not in err and "synthetic-query" not in err


def test_get_with_body_closes_connection(fixture_server):
    import socket

    with socket.create_connection(("127.0.0.1", fixture_server.server.server_port), timeout=2) as sock:
        sock.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")
        data = b""
        while chunk := sock.recv(4096):
            data += chunk
    assert b"connection: close" in data.lower()
