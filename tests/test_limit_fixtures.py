"""Independent measurements of finite fixture load, not collector verdicts."""

import json
from dataclasses import asdict
from html.parser import HTMLParser

import pytest


class DOMMetrics(HTMLParser):
    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input",
            "link", "meta", "param", "source", "track", "wbr"}
    IGNORED = {"script", "style", "template", "noscript"}

    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.elements = 0
        self.depth = 0
        self.stack = []
        self.text = ""
        self.feed(source)
        self.close()

    def handle_starttag(self, tag, attrs):
        self.elements += 1
        self.depth = max(self.depth, len(self.stack) + 1)
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        self.elements += 1
        self.depth = max(self.depth, len(self.stack) + 1)

    def handle_endtag(self, tag):
        if tag in self.stack:
            del self.stack[len(self.stack) - 1 - self.stack[::-1].index(tag):]

    def handle_data(self, data):
        if not any(tag in self.IGNORED for tag in self.stack):
            self.text += data


@pytest.mark.parametrize("size", [131071, 131072, 131073])
def test_utf8_size_boundary_is_exact(size):
    from isolation_tests.fixtures import boundary_html

    body = boundary_html("bytes", size)
    assert isinstance(body, bytes)
    assert len(body) == size
    source = body.decode("utf-8", errors="strict")
    assert DOMMetrics(source).elements > 0
    assert any(ord(char) > 127 for char in source), "exercise UTF-8, not only ASCII"


@pytest.mark.parametrize("metric,value", [
    ("elements", 1999), ("elements", 2000), ("elements", 2001),
    ("text", 15999), ("text", 16000), ("text", 16001),
    ("depth", 63), ("depth", 64), ("depth", 65),
])
def test_dom_boundaries_include_document_wrappers(metric, value):
    from isolation_tests.fixtures import boundary_html

    body = boundary_html(metric, value)
    measured = DOMMetrics(body.decode("utf-8", errors="strict"))
    observed = len(measured.text) if metric == "text" else getattr(measured, metric)
    assert observed == value
    assert len(body) <= 131072, "a DOM boundary must not first exceed the HTML cap"


@pytest.mark.parametrize("metric,value", [
    ("unknown", 131072), ("bytes", -1), ("bytes", 0),
    ("bytes", None), ("bytes", float("inf")), ("bytes", 131072.5),
    ("elements", -1), ("elements", 0), ("text", -1), ("text", 0),
    ("depth", -1), ("depth", 0), ("result", -1), ("result", 0),
    ("bytes", True), ("elements", 8 * 1024 * 1024 + 1),
])
def test_invalid_or_unbounded_boundary_requests_are_rejected(metric, value):
    from isolation_tests.fixtures import boundary_html

    with pytest.raises(ValueError):
        boundary_html(metric, value)


@pytest.mark.parametrize("value", [262143, 262144, 262145])
def test_result_fixture_is_a_dom_candidate_not_html_size_padding(value):
    from isolation_tests.fixtures import boundary_html

    body = boundary_html("result", value)
    measured = DOMMetrics(body.decode("utf-8", errors="strict"))
    assert len(body) <= 131072
    assert 0 < measured.elements <= 2000
    assert measured.depth <= 64
    assert len(measured.text) <= 16000
    assert b"<input" in body or b"<form" in body or b"<a " in body
    assert len(body) != value, "HTML byte length is not inspection JSON byte length"


@pytest.mark.parametrize("value", [262143, 262144, 262145])
def test_optional_ai_result_candidate_has_actual_serialized_boundary(value, monkeypatch):
    # Measure the candidate before output truncation with the real optional AI.
    # These test-local changes never alter an installed collector's limits.
    page = pytest.importorskip("ai.page", reason="blocked: optional AI package absent")
    from isolation_tests.fixtures import boundary_html

    monkeypatch.setattr(page, "MAX_INSPECTION_BYTES", 8 * 1024 * 1024)
    monkeypatch.setattr(page, "INSPECTION_TIMEOUT_SECONDS", 10)
    inspection = page.inspect_html(boundary_html("result", value).decode("utf-8"))
    serialized = json.dumps(asdict(inspection), ensure_ascii=False,
                            separators=(",", ":")).encode("utf-8")
    assert len(serialized) == value, "measure actual PageInspection JSON, never HTML bytes"


@pytest.mark.browser
@pytest.mark.parametrize("variant", ["dom-growth", "cpu-bursts"])
def test_resource_script_finishes_with_bounded_load(browser, variant):
    from isolation_tests.fixture_server import response_plan

    plan = response_plan("LIM-05", variant, {})
    page = browser.new_page()
    try:
        # Real DOM and fixture JavaScript; replace only time and scheduling.
        # A progressing performance clock makes a mistakenly endless busy loop
        # observable, and draining timers detects recursive unlimited growth.
        page.evaluate("""() => {
            window.fixtureTest = {queue: new Map(), next: 1, now: 0, maxBurst: 0};
            const state = window.fixtureTest;
            performance.now = () => ++state.now;
            window.setTimeout = (fn) => { const id = state.next++; state.queue.set(id, {fn}); return id; };
            window.setInterval = (fn) => { const id = state.next++; state.queue.set(id, {fn, repeat: true}); return id; };
            window.clearTimeout = window.clearInterval = (id) => state.queue.delete(id);
            window.requestAnimationFrame = (fn) => window.setTimeout(fn);
            window.cancelAnimationFrame = window.clearTimeout;
        }""")
        page.set_content(plan.body.decode("utf-8"))
        observed = page.evaluate("""() => {
            const state = window.fixtureTest;
            let callbacks = 0, peakNodes = document.querySelectorAll('*').length;
            state.maxBurst = state.now;
            while (state.queue.size && callbacks < 200) {
                const [id, timer] = state.queue.entries().next().value;
                if (!timer.repeat) state.queue.delete(id);
                const before = state.now;
                timer.fn(state.now);
                state.maxBurst = Math.max(state.maxBurst, state.now - before);
                peakNodes = Math.max(peakNodes, document.querySelectorAll('*').length);
                callbacks++;
            }
            return {pending: state.queue.size, callbacks, peakNodes,
                    elapsed: state.now, maxBurst: state.maxBurst};
        }""")
        assert observed["pending"] == 0, "fixture must end, not schedule forever"
        assert observed["peakNodes"] <= 4000
        if variant == "dom-growth":
            assert observed["peakNodes"] > 100, "fixture must generate actual DOM load"
        else:
            assert 50 <= observed["elapsed"] <= 40 * 55 + 100
            assert observed["maxBurst"] <= 55  # 50ms plus clock observation overhead
            assert observed["callbacks"] <= 40
    finally:
        page.close()
