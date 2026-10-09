"""Fixed-route HTTP fixtures and a secret-free receiver, standard library only."""

import argparse
import hashlib
import ipaddress
import json
import mimetypes
import os
import re
import socket
import ssl
import sys
import stat
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit

from .fixtures import (
    NET_VARIANTS, SAMPLE_BYTES, render_http, render_network, render_static,
)
from .receiver import RECEIVER_CASES, RUN_ID, write_receiver_event
from .targets import normalize_base


@dataclass(frozen=True)
class ResponsePlan:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    start_delay_s: float = 0
    chunk_interval_s: float = 0
    chunk_size: int = 4096
    max_duration_s: float = 20
    close_early: bool = False


@dataclass(frozen=True)
class FixtureConfig:
    host: str = '127.0.0.1'
    port: int = 0
    targets: dict[str, str] = field(default_factory=dict)
    static_root: Path | None = None
    log_path: Path | None = None
    tls_cert: Path | None = None
    tls_key: Path | None = None
    max_active: int = 4


class RequestRejected(ValueError):
    """The request itself is unusable (400); a plain ValueError means missing setup (503)."""


_HTML = "text/html; charset=utf-8"
_TEXT = "text/plain; charset=utf-8"
_PROBE_BODY = b"ok"


def _plan(status, body, content_type=_HTML, *extra, **options) -> ResponsePlan:
    return ResponsePlan(status, (("Content-Type", content_type), *extra), body, **options)


def _require_run_id(run_id):
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise RequestRejected("run_id is required and must be a safe identifier")
    return run_id


def _join(base, case_id: str, run_id: str) -> str:
    """Concrete receiver URL under a configured base without query or fragment."""
    if (not isinstance(base, str) or not base
            or re.search(r"[\x00-\x20\x7f\\%?#]", base)):
        raise ValueError("network target is not configured (preparation missing)")
    return f"{base.rstrip('/')}/v1/receive/{case_id}?run_id={run_id}"


def _receiver(targets, key: str, case_id: str, run_id) -> str:
    base = targets.get(key)
    if key == "forbidden_receiver":
        try:
            base = normalize_base(base, allow_loopback_http=True)
        except ValueError:
            raise ValueError("network target is not configured (preparation missing)") from None
    # Configuration is checked first so that missing setup is never reported as a bad request.
    _join(base, case_id, "x")
    return _join(base, case_id, _require_run_id(run_id))


def _redirect(location: str) -> ResponsePlan:
    return _plan(302, b"", _TEXT, ("Location", location))


def _hop_plan(case_id, variant, hops, run_id, hop):
    if (hop or 0) >= hops:
        return _plan(200, render_static("COL-01", "default"))
    query = {"hop": (hop or 0) + 1}
    if run_id and RUN_ID.fullmatch(run_id):
        query["run_id"] = run_id
    return _redirect(f"/v1/cases/{case_id}/{variant}?{urlencode(query)}")


def _loop_plan(run_id, hop):
    query = {"hop": 0 if hop else 1}
    if run_id and RUN_ID.fullmatch(run_id):
        query["run_id"] = run_id
    return _redirect(f"/v1/cases/NAV-03/loop?{urlencode(query)}")


def _nav04(variant, targets, run_id):
    url = _receiver(targets, "forbidden_receiver", "NAV-04", run_id)
    if variant == "http":
        return _redirect(url)
    script = json.dumps(url).replace("<", "\\u003c")
    body = ('<!doctype html>\n<html lang="ko"><head><meta charset="utf-8"><title>이동 중</title>'
            f"<script>location.replace({script});</script></head>"
            "<body><p>이동 중입니다.</p></body></html>\n").encode("utf-8")
    return _plan(200, body)


def _network(case_id, variant, targets, run_id):
    if case_id in {"NET-01", "NET-02", "NET-06"}:
        derived = {"forbidden_receiver":
                   _receiver(targets, "forbidden_receiver", case_id, run_id)}
        if case_id == "NET-06":
            derived["http_fixture"] = targets.get("http_fixture")
    else:
        key = variant.replace("-", "_")
        derived = {key: _receiver(targets, key, case_id, run_id)}
    body = render_network(case_id, variant, derived)
    if case_id == "NET-06" and variant in {"worker", "service-worker"}:
        # The script request carries no other context, so the page hands it the run id.
        marker = f"{variant}.js".encode()
        body = body.replace(marker + b'"', marker + f"?run_id={run_id}".encode() + b'"')
    return _plan(200, body)


def _net06_script(name, targets, run_id):
    url = _receiver(targets, "forbidden_receiver", "NET-06", run_id)
    script = json.dumps(url).replace("<", "\\u003c")
    body = (f"// {name}: one fixed request to the configured receiver\n"
            f"fetch({script}, {{mode: 'no-cors', cache: 'no-store'}}).catch(function () {{}});\n")
    return _plan(200, body.encode("utf-8"), "text/javascript; charset=utf-8")


def _build_registry():
    """(case_id, variant) -> builder(targets, run_id, hop). Later tasks add entries."""
    registry = {}
    for variant, hops in (("hops-1", 1), ("hops-5", 5)):
        registry[("NAV-02", variant)] = (
            lambda t, r, h, v=variant, n=hops: _hop_plan("NAV-02", v, n, r, h))
    registry[("NAV-03", "hops-6")] = lambda t, r, h: _hop_plan("NAV-03", "hops-6", 6, r, h)
    registry[("NAV-03", "loop")] = lambda t, r, h: _loop_plan(r, h)
    for variant in ("http", "js"):
        registry[("NAV-04", variant)] = lambda t, r, h, v=variant: _nav04(v, t, r)
    for case_id, variants in NET_VARIANTS.items():
        for variant in variants:
            registry[(case_id, variant)] = (
                lambda t, r, h, c=case_id, v=variant: _network(c, v, t, r))
    for name in ("worker.js", "service-worker.js"):
        registry[("NET-06", name)] = lambda t, r, h, n=name: _net06_script(n, t, r)
    for variant, status in (("403", 403), ("404", 404), ("500", 500),
                            ("block-page", 200), ("captcha-page", 200)):
        registry[("HTTP-01", variant)] = (
            lambda t, r, h, v=variant, s=status: _plan(s, render_http("HTTP-01", v)))
    registry[("HTTP-02", "wrong-mime")] = lambda t, r, h: _plan(
        200, render_http("HTTP-02", "wrong-mime"), _TEXT)
    registry[("HTTP-02", "invalid-utf8")] = lambda t, r, h: _plan(
        200, render_http("HTTP-02", "invalid-utf8"))
    registry[("HTTP-02", "truncated")] = lambda t, r, h: _plan(
        200, render_http("HTTP-02", "truncated"), close_early=True)
    registry[("DL-02", "attachment")] = lambda t, r, h: _plan(
        200, SAMPLE_BYTES, "application/octet-stream",
        ("Content-Disposition", 'attachment; filename="sample.apk"'))
    return registry


_REGISTRY = _build_registry()


def is_registered(case_id: str, variant: str) -> bool:
    return (case_id, variant) in _REGISTRY


def response_plan(case_id: str, variant: str, targets: dict[str, str], *,
                  run_id: str | None = None, hop: int | None = None) -> ResponsePlan:
    """Return the fixed response for one registered route.

    ValueError means the route needs setup that is absent; RequestRejected
    means the request lacks a usable run id. Neither embeds request data.
    """
    try:
        builder = _REGISTRY[(case_id, variant)]
    except KeyError:
        raise ValueError("unregistered case or variant") from None
    return builder(targets if isinstance(targets, dict) else {}, run_id, hop)


# --- static mirror -------------------------------------------------------

def _is_link(info) -> bool:
    return bool(stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _load_static(root: Path) -> tuple[Path, dict[str, str]]:
    """Only files named (with their hashes) by the builder's catalog are servable."""
    root = Path(os.path.abspath(root))
    try:
        files = json.loads((root / "catalog.json").read_text(encoding="utf-8"))["files"]
        if not isinstance(files, dict):
            raise TypeError
    except (OSError, ValueError, KeyError, TypeError):
        raise ValueError("static_root must contain a builder catalog.json") from None
    return root, {path: digest for path, digest in files.items()
                  if isinstance(path, str) and isinstance(digest, str)}


def _static_bytes(root: Path, allowed: dict[str, str], raw: str):
    """Return the mirror file for a once-decoded path, or None when not servable."""
    if raw != "catalog.json" and raw not in allowed:
        return None
    parts = raw.split("/")
    if any(part in {"", ".", ".."} or "\\" in part or "%" in part for part in parts):
        return None
    path = root.joinpath(*parts)
    current = root
    try:
        for part in parts:
            current = current / part
            if _is_link(os.lstat(current)):
                return None
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if raw != "catalog.json" and hashlib.sha256(data).hexdigest() != allowed[raw]:
        return None
    return data


# --- HTTP handling -------------------------------------------------------

def _diagnose(label: str, error: BaseException | None) -> None:
    """Report only a fixed route label and the exception class, never request data."""
    name = type(error).__name__ if error is not None else "unknown"
    try:
        sys.stderr.write(f"fixture error: route={label} type={name}\n")
        sys.stderr.flush()
    except (OSError, ValueError):
        pass


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 10
    server_version = "IsolationFixture"
    sys_version = ""

    # Nothing about a request may reach stderr or exceptions.
    def log_message(self, *args):
        pass

    def send_error(self, code, message=None, explain=None):
        self._respond(_plan(code, b"", _TEXT), close=True)

    def _respond(self, plan: ResponsePlan, close=False) -> int:
        """Write a response; return the number of body bytes actually sent."""
        limit = max(plan.max_duration_s, 0)
        deadline = time.monotonic() + limit
        if plan.start_delay_s > 0:
            time.sleep(min(plan.start_delay_s, limit))
        body = plan.body
        if close or plan.close_early:
            self.close_connection = True
        self.send_response(plan.status)
        for name, value in plan.headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        data = body[: len(body) // 2] if plan.close_early else body
        step = max(plan.chunk_size, 1)
        sent = 0
        try:
            while sent < len(data):
                chunk = data[sent: sent + step]
                self.wfile.write(chunk)
                sent += len(chunk)
                if sent < len(data) and plan.chunk_interval_s > 0:
                    time.sleep(plan.chunk_interval_s)
                if time.monotonic() > deadline:
                    self.close_connection = True
                    break
            self.wfile.flush()
        except OSError:
            self.close_connection = True
        return sent

    @staticmethod
    def _query(query: str) -> dict:
        """Return run_id/hop; a repeated parameter becomes '' so it fails validation."""
        pairs = parse_qsl(query, keep_blank_values=True)
        found = {}
        for name in ("run_id", "hop"):
            values = [value for key, value in pairs if key == name]
            found[name] = values[0] if len(values) == 1 else (None if not values else "")
        return found

    def _status(self, code):
        return self._respond(_plan(code, b"", _TEXT))

    def do_GET(self):
        # A GET body is never read; closing keeps it from being parsed as the next request.
        if self.headers.get("Content-Length", "0").strip() not in {"", "0"}                 or "Transfer-Encoding" in self.headers:
            self.close_connection = True
        try:
            return self._route()
        except Exception as error:
            # Name the failure class only: an exception message may quote request data.
            _diagnose("route", error)
            self.close_connection = True
            try:
                self._respond(_plan(500, b"", _TEXT))
            except OSError:
                pass

    def _route(self):
        parts = urlsplit(self.path)
        segments = parts.path.split("/")
        if parts.path == "/healthz":
            return self._respond(_plan(200, b"ok\n", _TEXT))
        if segments[:3] == ["", "v1", "static"] and len(segments) > 3:
            return self._static("/".join(segments[3:]))
        if segments[:3] == ["", "v1", "receive"] and len(segments) == 4:
            return self._receive(segments[3], parts.query)
        if segments[:3] == ["", "v1", "cases"] and len(segments) == 5:
            return self._case(segments[3], segments[4], parts.query)
        return self._status(404)

    def _case(self, case_id, variant, query):
        if not is_registered(case_id, variant):
            return self._status(404)
        found = self._query(query)
        hop = None
        if found["hop"] is not None:
            if not re.fullmatch(r"[0-9]{1,2}", found["hop"]):
                return self._status(400)
            hop = int(found["hop"])
        try:
            plan = response_plan(case_id, variant, self.server.fixture_config.targets,
                                 run_id=found["run_id"], hop=hop)
        except RequestRejected:
            plan = _plan(400, b"", _TEXT)
        except ValueError:
            plan = _plan(503, b"", _TEXT)
        return self._respond(plan)

    def _reject(self):
        # The request body is never read; closing the connection discards it.
        parts = urlsplit(self.path)
        segments = parts.path.split("/")
        sent = self._respond(_plan(405, b"", _TEXT, ("Allow", "GET")), close=True)
        if segments[:3] == ["", "v1", "receive"] and len(segments) == 4:
            self._record(segments[3], self._query(parts.query)["run_id"], sent)

    do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _reject

    def _receive(self, case_id, query):
        if case_id not in RECEIVER_CASES:
            return self._status(404)
        run_id = self._query(query)["run_id"]
        if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
            return self._status(400)
        # Record before answering so a 200 always means the event was stored.
        if not self._record(case_id, run_id, len(_PROBE_BODY)):
            return self._status(503)
        self._respond(_plan(200, _PROBE_BODY, _TEXT))

    def _record(self, case_id, run_id, sent) -> bool:
        """Store the event; False only when a log is configured but the write failed."""
        log_path = self.server.fixture_config.log_path
        if (log_path is None or case_id not in RECEIVER_CASES
                or not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id)
                or not re.fullmatch(r"[A-Z]{3,10}", self.command)):
            return log_path is None
        try:
            write_receiver_event(
                log_path, case_id=case_id, run_id=run_id, method=self.command,
                fixed_path=f"/v1/receive/{case_id}", bytes_sent=sent,
                at=datetime.now(timezone.utc).isoformat(),
            )
        except OSError as error:
            _diagnose("receiver-log", error)
            return False
        return True

    def _static(self, raw):
        data = None
        if self.server.static_files is not None:
            root, allowed = self.server.static_files
            data = _static_bytes(root, allowed, unquote(raw))
        if data is None:
            return self._status(404)
        kind = mimetypes.guess_type(unquote(raw))[0] or "application/octet-stream"
        if kind.startswith("text/"):
            kind += "; charset=utf-8"
        return self._respond(_plan(200, data, kind))


class _TLSHandler(_Handler):
    def setup(self):
        # The handshake runs in this request's thread, never in accept().
        self.request.settimeout(self.timeout)
        self.request.do_handshake()
        super().setup()


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def handle_error(self, request, client_address):
        _diagnose("connection", sys.exc_info()[1])


class _Server6(_Server):
    address_family = socket.AF_INET6


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.lower().rstrip(".") == "localhost"


def make_server(config: FixtureConfig) -> _Server:
    """Validate configuration, then bind. Nothing is bound on a configuration error."""
    if bool(config.tls_cert) != bool(config.tls_key):
        raise ValueError("tls_cert and tls_key must be configured together")
    tls = bool(config.tls_cert)
    if not _is_loopback(config.host) and not tls:
        raise ValueError("binding beyond loopback requires TLS")
    if config.max_active < 1:
        raise ValueError("max_active must be positive")
    static = _load_static(config.static_root) if config.static_root is not None else None
    context = None
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(config.tls_cert), str(config.tls_key))
    cls = _Server6 if ":" in config.host else _Server
    server = cls((config.host, config.port), _TLSHandler if tls else _Handler)
    if context is not None:
        server.socket = context.wrap_socket(
            server.socket, server_side=True, do_handshake_on_connect=False)
    server.fixture_config = config
    server.static_files = static
    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Serve fixed synthetic HTTP test fixtures")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--static-root", type=Path)
    parser.add_argument("--log", type=Path, help="receiver JSONL path")
    parser.add_argument("--tls-cert", type=Path)
    parser.add_argument("--tls-key", type=Path)
    parser.add_argument("--max-active", type=int, default=4)
    parser.add_argument("--target", action="append", default=[], metavar="NAME=URL")
    args = parser.parse_args(argv)
    targets = {}
    for item in args.target:
        name, separator, value = item.partition("=")
        if not separator or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name):
            parser.exit(2, "invalid --target; expected NAME=URL\n")
        targets[name] = value
    try:
        server = make_server(FixtureConfig(
            host=args.host, port=args.port, targets=targets, static_root=args.static_root,
            log_path=args.log, tls_cert=args.tls_cert, tls_key=args.tls_key,
            max_active=args.max_active,
        ))
    except (ValueError, OSError, ssl.SSLError) as error:
        parser.exit(2, f"cannot start: {type(error).__name__}\n")
    print(f"listening on port {server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
