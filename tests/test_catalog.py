"""Public catalog contracts and real Chromium interaction under a Pages prefix."""

import hashlib
import json
import re
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

import pytest


ROOT = Path(__file__).resolve().parents[1]
COMMIT_SHA = "c" * 40


def cases():
    from isolation_tests.manifest import load_cases

    return load_cases(ROOT / "tools/isolation-tests/cases.json")


def atoms(value):
    # The catalog's nesting is not a public API. Inspect its public semantics.
    if isinstance(value, dict):
        return set(value).union(*(atoms(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(atoms(item) for item in value))
    return {value} if isinstance(value, str) else set()


def expect(locator):
    from playwright.sync_api import expect as playwright_expect

    return playwright_expect(locator)


def test_catalog_lists_every_case_and_fixed_variant_with_source_commit(tmp_path):
    from isolation_tests.build_pages import build_site

    manifest = cases()
    output = tmp_path / "public"
    build_site(manifest, output, commit_sha=COMMIT_SHA)
    values = atoms(json.loads((output / "catalog.json").read_text(encoding="utf-8")))
    assert COMMIT_SHA in values
    assert {case.id for case in manifest} <= values
    assert {variant for case in manifest for variant in case.variants} <= values
    assert {case.group for case in manifest} <= values
    assert {case.title for case in manifest} <= values
    assert {case.message for case in manifest if case.message} <= values


def test_catalog_static_hashes_match_published_variant_bytes(tmp_path):
    from isolation_tests.build_pages import build_site

    manifest = tuple(case for case in cases() if case.execution_kind == "page")
    output = tmp_path / "public"
    build_site(manifest, output, commit_sha=COMMIT_SHA)
    values = atoms(json.loads((output / "catalog.json").read_text(encoding="utf-8")))
    for case in manifest:
        for variant in case.variants:
            page = output / f"v1/cases/{case.id.lower()}/{variant}.html"
            assert page.is_file()
            assert hashlib.sha256(page.read_bytes()).hexdigest() in values


def test_public_outputs_omit_operational_targets_token_references_and_full_config(tmp_path, monkeypatch):
    from isolation_tests.build_pages import build_site

    secret = "synthetic-secret-avoid-public-catalog-734"
    monkeypatch.setenv("ISOLATION_TEST_TOKEN", secret)
    internal = "https://192.168.50.12/synthetic-operational-target-734"
    # Internal destinations belong to operational rendering, never the catalog.
    manifest = tuple(replace(case, expected_observations={"internal_marker": internal})
                     if case.id == "NET-03" else case for case in cases())
    output = tmp_path / "public"
    build_site(manifest, output, commit_sha=COMMIT_SHA)
    forbidden = (secret, internal, "ISOLATION_TEST_TOKEN", "token_env", "collector_url",
                 "evidence_dir", "backend_contract", "169.254.169.254")
    for path in output.rglob("*"):
        if path.is_file():
            body = path.read_bytes()
            assert all(marker.encode("utf-8") not in body for marker in forbidden), path


def test_catalog_shell_and_local_assets_are_built_for_publication(tmp_path):
    from isolation_tests.build_pages import build_site

    output = tmp_path / "public"
    hashes = build_site(cases(), output, commit_sha=COMMIT_SHA)
    for name in ("index.html", "assets/catalog.js", "assets/styles.css"):
        assert name in hashes
        assert (output / name).is_file()
        assert hashes[name] == hashlib.sha256((output / name).read_bytes()).hexdigest()


@pytest.fixture
def catalog_page(browser, site_url):
    context = browser.new_context()
    page = context.new_page()
    response = page.goto(site_url)
    assert response is not None and response.status == 200
    expect(page.get_by_text("COL-01", exact=False).first).to_be_visible()
    try:
        yield page
    finally:
        context.close()


def search(page):
    # A visible semantic search control is part of the catalog's user contract.
    field = page.get_by_role("searchbox")
    if field.count() == 0:
        field = page.get_by_role("textbox", name=re.compile("검색|search", re.I))
    expect(field).to_be_visible()
    return field


@pytest.mark.browser
def test_catalog_loads_all_case_ids_without_starting_tests_or_api_auth(catalog_page, site_url):
    page = catalog_page
    for case in cases():
        expect(page.get_by_text(case.id, exact=False).first).to_be_visible()
    assert page.locator('input[type="password"]').count() == 0
    assert page.get_by_role("textbox", name=re.compile("token|토큰|authorization|API 인증", re.I)).count() == 0
    urls = page.evaluate("performance.getEntriesByType('resource').map(entry => entry.name)")
    assert any(urlsplit(url).path.endswith("/catalog.json") for url in urls)
    assert all(url.startswith(site_url) for url in urls)
    assert not any("/v1/cases/" in url or "/collect" in url or "/v1/receive/" in url for url in urls)


@pytest.mark.browser
def test_catalog_search_matches_id_title_and_message(catalog_page):
    page = catalog_page
    field = search(page)
    baseline = next(case for case in cases() if case.id == "COL-01")
    for query in (baseline.id, baseline.title, baseline.message):
        assert query
        field.fill(query)
        expect(page.get_by_text(baseline.id, exact=False).first).to_be_visible()
    field.fill("ANA-03")
    expect(page.get_by_text("ANA-03", exact=False).first).to_be_visible()
    expect(page.get_by_text("COL-01", exact=False).first).to_be_hidden()
    field.fill("no-such-case-search-marker-714")
    expect(page.get_by_text("ANA-03", exact=False).first).to_be_hidden()
    field.fill("")
    expect(page.get_by_text("COL-01", exact=False).first).to_be_visible()


@pytest.mark.browser
def test_catalog_category_filter_and_search_work_together(catalog_page):
    page = catalog_page
    category = page.get_by_role("combobox").first
    expect(category).to_be_visible()
    options = category.locator("option").evaluate_all("nodes => nodes.map(node => ({value: node.value, text: node.textContent}))")
    network = next(option for option in options
                   if option["value"] == "network" or re.search("네트워크|network", option["text"], re.I))
    category.select_option(network["value"])
    expect(page.get_by_text("NET-01", exact=False).first).to_be_visible()
    expect(page.get_by_text("COL-01", exact=False).first).to_be_hidden()
    search(page).fill("NET-02")
    expect(page.get_by_text("NET-02", exact=False).first).to_be_visible()
    expect(page.get_by_text("NET-01", exact=False).first).to_be_hidden()


@pytest.mark.browser
def test_catalog_static_links_and_form_targets_preserve_repository_prefix(catalog_page, site_url):
    page = catalog_page
    links = page.locator("a[href]").evaluate_all("nodes => nodes.map(node => node.href)")
    samples = [url for url in links if "/v1/cases/" in urlsplit(url).path]
    assert samples
    assert all(url.startswith(site_url) for url in samples)
    assert all(urlsplit(url).netloc == urlsplit(site_url).netloc for url in samples)
    col03 = next(url for url in samples if "/col-03/" in url)
    response = page.goto(col03)
    assert response is not None and response.status == 200
    destinations = page.locator("form[action], button[formaction]").evaluate_all(
        "nodes => nodes.map(node => node.tagName === 'FORM' ? node.action : node.formAction)"
    )
    assert destinations and all(url.startswith(site_url) for url in destinations)


@pytest.mark.browser
def test_unconfigured_http_cases_have_no_active_link_or_enabled_url_copy(catalog_page):
    page = catalog_page
    search(page).fill("NET-01")
    expect(page.get_by_text("NET-01", exact=False).first).to_be_visible()
    assert page.locator("a[href]").filter(has_text=re.compile("NET-01|열기|open", re.I)).filter(visible=True).count() == 0
    assert page.locator('a[href*="/v1/cases/NET-01"], a[href*="/v1/cases/net-01"]').filter(visible=True).count() == 0
    copies = page.get_by_role("button", name=re.compile("URL.*복사|copy.*URL", re.I))
    assert copies.count() >= 1
    for button in copies.all():
        if button.is_visible():
            expect(button).to_be_disabled()


@pytest.mark.browser
@pytest.mark.parametrize("failure", ["absent", "rejected"])
@pytest.mark.parametrize("kind", ["url", "message"])
def test_copy_falls_back_to_selected_readonly_text_when_clipboard_unavailable(browser, site_url, failure, kind):
    context = browser.new_context()
    try:
        page = context.new_page()
        if failure == "absent":
            page.add_init_script("Object.defineProperty(navigator, 'clipboard', {value: undefined, configurable: true});")
        else:
            page.add_init_script("""Object.defineProperty(navigator, 'clipboard', {
                value: {writeText: async () => { throw new DOMException('denied', 'NotAllowedError'); }},
                configurable: true
            });""")
        page.goto(site_url)
        expect(page.get_by_text("COL-01", exact=False).first).to_be_visible()
        search(page).fill("COL-01")
        name = re.compile("URL.*복사|copy.*URL", re.I) if kind == "url" else re.compile("문자.*복사|메시지.*복사|copy.*message", re.I)
        button = page.get_by_role("button", name=name).filter(visible=True).first
        expect(button).to_be_enabled()
        button.click()
        fallback = page.locator("textarea[readonly], input[readonly]").filter(visible=True).last
        expect(fallback).to_be_visible()
        value = fallback.input_value()
        if kind == "url":
            assert value.startswith(site_url)
            assert "/v1/cases/col-01/" in urlsplit(value).path
        else:
            assert value == next(case.message for case in cases() if case.id == "COL-01")
        assert fallback.evaluate("element => [element.selectionStart, element.selectionEnd]") == [0, len(value)]
        assert fallback.evaluate("element => element === document.activeElement")
    finally:
        context.close()


@pytest.mark.browser
def test_catalog_renders_untrusted_json_strings_as_text_without_execution(browser, site_url):
    payload = '<img src="https://outside.invalid/catalog-injection" onerror="window.__catalogXss=1">'
    context = browser.new_context()
    try:
        page = context.new_page()
        attempted = []
        page.on("request", lambda request: attempted.append(request.url))

        def alter_catalog(route):
            response = route.fetch()
            data = response.json()

            def poison(value):
                if isinstance(value, dict):
                    if value.get("id") == "COL-01":
                        value["title"] = payload
                        value["description"] = payload
                        value["message"] = payload
                    for item in value.values():
                        poison(item)
                elif isinstance(value, list):
                    for item in value:
                        poison(item)

            poison(data)
            route.fulfill(response=response, json=data)

        page.route("**/catalog.json", alter_catalog)
        page.goto(site_url)
        expect(page.get_by_text(payload, exact=True).first).to_be_visible()
        assert page.locator('img[src*="catalog-injection"]').count() == 0
        assert page.evaluate("window.__catalogXss === undefined")
        assert not any("catalog-injection" in url for url in attempted)
    finally:
        context.close()
