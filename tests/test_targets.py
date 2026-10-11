"""Destination policy and fixed network fixture contracts, without remote calls."""

import re
from dataclasses import replace
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from isolation_tests.model import CaseSpec, RuntimeConfig


ROOT = Path(__file__).resolve().parents[1]
NETWORK_VARIANTS = {
    "NET-01": ("img", "script", "iframe", "fetch"),
    "NET-02": ("action", "formaction"),
    "NET-03": ("loopback", "private", "link-local", "main-public", "isolation-public"),
    "NET-04": ("shared-ip-host", "same-host-path"),
    "NET-06": ("websocket", "worker", "service-worker"),
}


def page_case(**changes):
    case = CaseSpec(
        id="COL-01", group="collection", title="수집 기준", description="합성 표본",
        execution_kind="page", target_key="pages",
        relative_path="v1/cases/col-01/index.html", variants=("default",),
        required_capabilities=(), message="합성 문자", expected_observations={},
        expected_analysis={}, required_evidence=(), risk_level="basic",
        max_requests=1, recovery_case=None,
    )
    return replace(case, **changes)


def config(**changes):
    value = RuntimeConfig(
        bases={"pages": "https://pages.invalid/renamed-project/"},
        collector_url=None, token_env=None, ca_file=None, limits={},
        capabilities=frozenset(), evidence_dir=None, backend_contract=None,
    )
    return replace(value, **changes)


def network_targets():
    return {
        "http_fixture": "https://allowed.invalid/project/",
        "forbidden_receiver": "https://receiver.invalid/v1/receive/synthetic?run_id=fixture-test",
        "loopback": "https://127.0.0.1/synthetic-loopback",
        "private": "https://192.168.50.12/synthetic-private",
        "link_local": "https://169.254.50.12/synthetic-link-local",
        "main_public": "https://main.invalid/synthetic-main",
        "isolation_public": "https://isolation.invalid/synthetic-isolation",
        "shared_ip_host": "https://shared.invalid/synthetic-shared",
        "same_host_path": "https://allowed.invalid/outside-allowed-project/synthetic",
    }


class NetworkDocument(HTMLParser):
    def __init__(self, body):
        super().__init__(convert_charrefs=True)
        self.elements = []
        self.script = []
        self.in_script = False
        self.feed(body.decode("utf-8"))

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))
        if tag == "script":
            self.in_script = True

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_script = False

    def handle_data(self, value):
        if self.in_script:
            self.script.append(value)

    def find(self, tag):
        return [attrs for name, attrs in self.elements if name == tag]


@pytest.mark.parametrize("prefix", ["renamed-project", "folder/project"])
@pytest.mark.parametrize("trailing_slash", ["", "/"])
def test_case_url_preserves_project_prefix_host_and_port(prefix, trailing_slash):
    from isolation_tests.targets import case_url

    cfg = config(bases={"pages": f"https://pages.invalid:9443/{prefix}{trailing_slash}"})
    result = case_url(page_case(), "default", cfg, "run-test_01")
    parts = urlsplit(result)
    assert (parts.scheme, parts.hostname, parts.port) == ("https", "pages.invalid", 9443)
    assert parts.path == f"/{prefix}/v1/cases/col-01/index.html"
    assert parse_qs(parts.query) == {"run_id": ["run-test_01"]}
    assert not parts.fragment


def test_case_url_selects_registered_page_variant():
    from isolation_tests.targets import case_url

    case = page_case(id="ANA-03", relative_path="v1/cases/ana-03/index.html", variants=("password", "otp"))
    result = case_url(case, "otp", config(), "test")
    assert urlsplit(result).path == "/renamed-project/v1/cases/ana-03/otp.html"


def test_http_fixture_variant_uses_configured_prefix_and_manifest_case_id():
    from isolation_tests.targets import case_url

    case = page_case(id="NET-01", execution_kind="http_fixture", target_key="http_fixture",
                     relative_path="v1/cases/NET-01", variants=NETWORK_VARIANTS["NET-01"])
    cfg = config(bases={"http_fixture": "https://allowed.invalid/test-root"})
    assert case_url(case, "fetch", cfg, "test") == "https://allowed.invalid/test-root/v1/cases/NET-01/fetch?run_id=test"


@pytest.mark.parametrize("path", [
    "/v1/cases/col-01/index.html", "//outside.invalid/path", "../outside.html",
    "v1/../../outside.html", "v1/cases/../col-01/index.html", r"..\outside.html",
    r"v1\..\outside.html", "https://outside.invalid/path", "javascript:alert(1)",
    "https://user:secret@outside.invalid/path", "//user@outside.invalid/path",
    "%2f%2foutside.invalid/path", "%2e%2e/outside.html", "%252e%252e/outside.html",
    "v1/%2e%2e/escape.html", "v1/%5c..%5cescape.html", "v1/%252foutside.html",
    "v1/cases/col-01/index.html?destination=https://outside.invalid", "v1/cases/x#fragment",
    "v1/cases/x\n.html", "v1/cases/%00.html",
])
def test_case_url_rejects_unsafe_relative_paths(path):
    from isolation_tests.targets import case_url

    with pytest.raises(ValueError):
        case_url(page_case(relative_path=path), "default", config(), "test")


@pytest.mark.parametrize("base", [
    "", "//pages.invalid/project/", "ftp://pages.invalid/project/", "javascript:alert(1)",
    "http://pages.invalid/project/", "https://user:secret@pages.invalid/project/",
    "https://pages.invalid:99999/project/", "https://pages.invalid/project/?leak=1",
    "https://pages.invalid/project/#fragment", "https://pages.invalid/project/../outside/",
    "https://pages.invalid/project/%2e%2e/outside/", "https://pages.invalid/project/%252e%252e/outside/",
    "https://pages.invalid/project\\outside/", "https://pages.invalid/\nproject/",
])
def test_case_url_rechecks_base_even_when_config_constructed_directly(base):
    from isolation_tests.targets import case_url

    with pytest.raises(ValueError):
        case_url(page_case(), "default", config(bases={"pages": base}), "test")


@pytest.mark.parametrize("run_id", ["", "x" * 65, "a/b", "../run", "a?b", "a&x=1", "a#b", "a b", "한글", "test\n", "a%2fb"])
def test_case_url_rejects_invalid_run_id(run_id):
    from isolation_tests.targets import case_url

    with pytest.raises(ValueError):
        case_url(page_case(), "default", config(), run_id)


@pytest.mark.parametrize("run_id", ["x", "x" * 64, "A0_-test"])
def test_case_url_accepts_run_id_boundaries(run_id):
    from isolation_tests.targets import case_url

    assert parse_qs(urlsplit(case_url(page_case(), "default", config(), run_id)).query) == {"run_id": [run_id]}


@pytest.mark.parametrize("variant", ["unknown", "../default", "default?url=outside", "default/extra"])
def test_case_url_rejects_unregistered_variant(variant):
    from isolation_tests.targets import case_url

    with pytest.raises(ValueError):
        case_url(page_case(), variant, config(), "test")


def test_case_url_missing_target_is_preparation_failure_instead_of_dummy_url():
    from isolation_tests.targets import case_url

    with pytest.raises(ValueError, match=r"(?i)(target|missing|configured|blocked|preparation)"):
        case_url(page_case(), "default", config(bases={}), "test")


def test_case_url_loopback_http_requires_explicit_local_opt_in():
    from isolation_tests.targets import case_url

    cfg = config(bases={"pages": "http://127.0.0.1:8080/local-project/"})
    with pytest.raises(ValueError):
        case_url(page_case(), "default", cfg, "test")
    allowed = case_url(page_case(), "default", replace(cfg, allow_loopback_http=True), "test")
    assert allowed == "http://127.0.0.1:8080/local-project/v1/cases/col-01/index.html?run_id=test"


@pytest.mark.parametrize("case_id,variant", [(case_id, variant) for case_id, variants in NETWORK_VARIANTS.items() for variant in variants])
def test_render_network_is_fixed_deterministic_utf8_without_response_collection(case_id, variant):
    from isolation_tests.fixtures import render_network

    targets = network_targets()
    first = render_network(case_id, variant, targets)
    assert isinstance(first, bytes) and first == render_network(case_id, variant, targets)
    document = NetworkDocument(first)
    assert document.find("html")
    assert any(attrs.get("charset", "").lower() == "utf-8" for attrs in document.find("meta"))
    script = "\n".join(document.script)
    # A network probe must not read/relay received content or retry.
    assert not re.search(r"\.(?:text|json|arrayBuffer|blob)\s*\(|\b(?:sendBeacon|setInterval)\s*\(", script)
    assert not re.search(r"\b(?:for|while)\s*\(", script)
    assert not re.search(r"\.(?:submit|requestSubmit)\s*\(", script)
    assert not re.search(r"\b(?:eval|Function)\s*\(", script)


@pytest.mark.parametrize("variant", NETWORK_VARIANTS["NET-01"])
def test_net01_contains_exactly_one_selected_request_destination(variant):
    from isolation_tests.fixtures import render_network

    targets = network_targets()
    body = render_network("NET-01", variant, targets)
    document = NetworkDocument(body)
    resources = [(tag, attrs["src"]) for tag, attrs in document.elements
                 if tag in {"img", "script", "iframe"} and attrs.get("src")]
    script = "\n".join(document.script)
    if variant == "fetch":
        assert resources == []
        assert len(re.findall(r"\bfetch\s*\(", script)) == 1
        assert targets["forbidden_receiver"] in script
    else:
        assert resources == [(variant, targets["forbidden_receiver"])]
        assert not re.search(r"\bfetch\s*\(", script)


@pytest.mark.parametrize("variant", NETWORK_VARIANTS["NET-02"])
def test_net02_exposes_form_destination_without_automatic_submission(variant):
    from isolation_tests.fixtures import render_network

    document = NetworkDocument(render_network("NET-02", variant, network_targets()))
    assert document.find("form") and document.find("input")
    if variant == "action":
        destinations = [attrs.get("action") for attrs in document.find("form")]
    else:
        destinations = [attrs.get("formaction") for attrs in document.find("button") + document.find("input") if attrs.get("formaction")]
    assert destinations == [network_targets()["forbidden_receiver"]]
    assert not re.search(r"\bfetch\s*\(|\.(?:submit|requestSubmit)\s*\(", "\n".join(document.script))
    assert not any(name.startswith("on") for _, attrs in document.elements for name in attrs)


@pytest.mark.parametrize("case_id,variant", [("NET-03", variant) for variant in NETWORK_VARIANTS["NET-03"]] + [("NET-04", variant) for variant in NETWORK_VARIANTS["NET-04"]])
def test_private_and_scope_variants_use_only_the_selected_explicit_target(case_id, variant):
    from isolation_tests.fixtures import render_network

    targets = network_targets()
    document = NetworkDocument(render_network(case_id, variant, targets))
    script = "\n".join(document.script)
    resources = [attrs["src"] for tag, attrs in document.elements
                 if tag in {"img", "script", "iframe"} and attrs.get("src")]
    # Both a single DOM resource and a single fetch reproduce access; the design
    # does not mandate one of those mechanisms for private/scope cases.
    assert len(resources) + len(re.findall(r"\bfetch\s*\(", script)) == 1
    selected = targets[variant.replace("-", "_")]
    assert selected in resources or selected in script
    attempted_destinations = "\n".join(resources) + "\n" + script
    assert all(value not in attempted_destinations for key, value in targets.items()
               if key not in {variant.replace("-", "_"), "http_fixture"})


@pytest.mark.parametrize("variant", NETWORK_VARIANTS["NET-06"])
def test_net06_attempts_only_its_fixed_connection_mechanism(variant):
    from isolation_tests.fixtures import render_network

    targets = network_targets()
    document = NetworkDocument(render_network("NET-06", variant, targets))
    script = "\n".join(document.script)
    counts = {
        "websocket": len(re.findall(r"\bnew\s+WebSocket\s*\(", script)),
        "worker": len(re.findall(r"\bnew\s+Worker\s*\(", script)),
        "service-worker": len(re.findall(r"serviceWorker\s*\.\s*register\s*\(", script)),
    }
    assert counts == {name: int(name == variant) for name in counts}
    assert not re.search(r"\bfetch\s*\(", script)
    if variant == "websocket":
        assert targets["forbidden_receiver"].replace("https:", "wss:", 1) in script
    else:
        assert targets["http_fixture"] in script
        assert targets["forbidden_receiver"] not in script


@pytest.mark.parametrize("case_id,variant", [("NET-00", "fetch"), ("NET-01", "unknown"), ("NET-03", "../private"), ("COL-01", "default")])
def test_network_renderer_rejects_noncontract_cases_and_variants(case_id, variant):
    from isolation_tests.fixtures import render_network

    with pytest.raises(ValueError):
        render_network(case_id, variant, network_targets())


@pytest.mark.parametrize("case_id,variant", [(case_id, variant) for case_id, variants in NETWORK_VARIANTS.items() for variant in variants])
def test_network_renderer_without_required_destination_is_preparation_failure(case_id, variant):
    from isolation_tests.fixtures import render_network

    with pytest.raises(ValueError, match=r"(?i)(target|missing|configured|blocked|preparation)"):
        render_network(case_id, variant, {})


@pytest.mark.browser
@pytest.mark.parametrize("variant", NETWORK_VARIANTS["NET-01"])
def test_net01_browser_attempts_selected_destination_once_without_forwarding_response(browser, variant):
    from isolation_tests.fixtures import render_network

    targets = network_targets()
    document_url = targets["http_fixture"] + "v1/cases/NET-01/" + variant
    body = render_network("NET-01", variant, targets)
    context = browser.new_context()
    try:
        page = context.new_page()
        attempts = []

        def serve(route):
            if route.request.url == document_url:
                route.fulfill(status=200, content_type="text/html; charset=utf-8", body=body)
            else:
                attempts.append((route.request.method, route.request.url))
                # Every destination stays inside the test route handler.
                route.fulfill(status=200, content_type="text/plain", body="synthetic-response-not-to-forward",
                              headers={"Access-Control-Allow-Origin": "*"})

        page.route("**/*", serve)
        page.goto(document_url)
        page.wait_for_timeout(300)
        assert attempts == [("GET", targets["forbidden_receiver"])]
        assert "synthetic-response-not-to-forward" not in page.locator("body").inner_text()
    finally:
        context.close()


@pytest.mark.browser
@pytest.mark.parametrize("variant", NETWORK_VARIANTS["NET-02"])
def test_net02_browser_records_form_destination_without_sending_a_request(browser, variant):
    from isolation_tests.fixtures import render_network

    targets = network_targets()
    document_url = targets["http_fixture"] + "v1/cases/NET-02/" + variant
    body = render_network("NET-02", variant, targets)
    context = browser.new_context()
    try:
        page = context.new_page()
        attempts = []
        submit_events = []
        page.expose_function("recordSyntheticSubmission", lambda: submit_events.append(True))
        page.add_init_script("document.addEventListener('submit', () => window.recordSyntheticSubmission(), true);")

        def serve(route):
            if route.request.url == document_url:
                route.fulfill(status=200, content_type="text/html; charset=utf-8", body=body)
            else:
                attempts.append(route.request.url)
                route.fulfill(status=200, body="")

        page.route("**/*", serve)
        page.goto(document_url)
        page.wait_for_timeout(300)
        destinations = page.locator("form[action]").evaluate_all("nodes => nodes.map(node => node.action)") if variant == "action" else page.locator("[formaction]").evaluate_all("nodes => nodes.map(node => node.formAction)")
        assert targets["forbidden_receiver"] in destinations
        assert attempts == [] and submit_events == []
    finally:
        context.close()
