"""Real browser behavior of public synthetic pages, never EC2 isolation evidence."""

import json
from urllib.parse import urlsplit

import pytest


pytestmark = pytest.mark.browser


def expect(actual):
    # Default test collection does not require the optional browser dependency.
    from playwright.sync_api import expect as playwright_expect

    return playwright_expect(actual)


@pytest.fixture
def context(browser):
    instance = browser.new_context()
    yield instance
    instance.close()


def _goto(page, site_url, relative_path):
    response = page.goto(site_url + relative_path)
    assert response is not None and response.status == 200


def _has_seed_by_store(context):
    state = context.storage_state(indexed_db=True)
    origins = state["origins"]
    return {
        "cookie": any(item["value"] == "isolation-test" for item in state["cookies"]),
        "localStorage": any(
            item["value"] == "isolation-test"
            for origin in origins
            for item in origin["localStorage"]
        ),
        "IndexedDB": any(
            "isolation-test" in json.dumps(record.get("value"), ensure_ascii=False)
            for origin in origins
            for database in origin.get("indexedDB", [])
            for store in database["stores"]
            for record in store["records"]
        ),
    }


def test_delayed_form_is_rendered_after_timer(context, site_url):
    page = context.new_page()
    page.add_init_script("""
        window.__testReadyAt = null;
        const observer = new MutationObserver(() => {
            if (document.querySelector('[data-test="js-ready"]')) {
                window.__testReadyAt = performance.now();
                observer.disconnect();
            }
        });
        observer.observe(document, {childList: true, subtree: true});
    """)
    _goto(page, site_url, "v1/cases/col-04/index.html")
    page.locator('[data-test="js-ready"]').wait_for(timeout=2000)
    expect(page.get_by_label("동적 인증번호")).to_have_attribute("name", "otp")
    assert page.locator('input[name="otp"]').count() == 1
    # Allow scheduling tolerance, but reject an immediately rendered field.
    assert page.evaluate("window.__testReadyAt") >= 250


def test_iframe_has_distinct_content_inside_repository_prefix(context, site_url):
    page = context.new_page()
    _goto(page, site_url, "v1/cases/col-05/iframe.html")
    iframe = page.locator("iframe")
    expect(iframe).to_have_count(1)
    child = iframe.element_handle().content_frame()
    assert child is not None
    expect(child.locator('[data-test="iframe-marker"]')).to_be_visible()
    assert child.url.startswith(site_url)
    assert urlsplit(child.url).netloc == urlsplit(site_url).netloc
    assert page.locator('[data-test="iframe-marker"]').count() == 0


def test_open_shadow_content_is_accessible(context, site_url):
    page = context.new_page()
    _goto(page, site_url, "v1/cases/col-05/open-shadow.html")
    marker = page.locator('[data-test="open-shadow-marker"]')
    expect(marker).to_be_visible()
    assert marker.evaluate("element => element.getRootNode() instanceof ShadowRoot")
    assert marker.evaluate("element => element.getRootNode().mode") == "open"


def test_closed_shadow_is_identified_as_unconfirmed_without_forcing_access(context, site_url):
    page = context.new_page()
    _goto(page, site_url, "v1/cases/col-05/closed-shadow.html")
    host = page.locator('[data-test="closed-shadow-host"]')
    expect(host).to_be_visible()
    assert host.evaluate("element => element.shadowRoot") is None
    expect(page.locator("body")).to_contain_text("미확인")
    assert page.locator('[data-test="closed-shadow-marker"]').count() == 0
    assert page.locator('[data-test="open-shadow-marker"]').count() == 0


@pytest.mark.parametrize("variant", ["js", "meta"])
def test_navigation_reaches_baseline_inside_repository_prefix(context, site_url, variant):
    page = context.new_page()
    page.goto(site_url + f"v1/cases/nav-01/{variant}.html")
    page.wait_for_url(site_url + "v1/cases/col-01/index.html", timeout=3000)
    expect(page).to_have_title("수집 기준")
    expect(page.locator("body")).to_contain_text("배송 상태: 배송 중")


def test_seed_ready_means_all_three_stores_are_written(context, site_url):
    page = context.new_page()
    _goto(page, site_url, "v1/cases/ses-01/seed.html")
    page.locator('[data-test="seed-ready"]').wait_for(timeout=3000)
    assert _has_seed_by_store(context) == {
        "cookie": True, "localStorage": True, "IndexedDB": True
    }


def test_new_context_does_not_inherit_any_seed_store(browser, site_url):
    first = browser.new_context()
    try:
        page = first.new_page()
        _goto(page, site_url, "v1/cases/ses-01/seed.html")
        page.locator('[data-test="seed-ready"]').wait_for(timeout=3000)
    finally:
        first.close()
    second = browser.new_context()
    try:
        page = second.new_page()
        _goto(page, site_url, "v1/cases/ses-01/read.html")
        expect(page.locator('[data-test="session-result"]')).to_have_text("empty")
        assert _has_seed_by_store(second) == {
            "cookie": False, "localStorage": False, "IndexedDB": False
        }
    finally:
        second.close()


def test_reused_context_observes_retained_seed(context, site_url):
    page = context.new_page()
    _goto(page, site_url, "v1/cases/ses-01/seed.html")
    page.locator('[data-test="seed-ready"]').wait_for(timeout=3000)
    _goto(page, site_url, "v1/cases/ses-01/read.html")
    expect(page.locator('[data-test="session-result"]')).to_have_text("retained")


@pytest.mark.parametrize("keep", ["cookie", "localStorage", "IndexedDB"])
def test_read_checks_each_storage_independently(context, site_url, keep):
    page = context.new_page()
    _goto(page, site_url, "v1/cases/ses-01/seed.html")
    page.locator('[data-test="seed-ready"]').wait_for(timeout=3000)
    # Leave the seed document to release its own IndexedDB connections before
    # removing the two stores excluded from this negative control.
    _goto(page, site_url, "v1/cases/col-01/index.html")
    if keep != "cookie":
        context.clear_cookies()
    page.evaluate("""async keep => {
        if (keep !== 'localStorage') localStorage.clear();
        if (keep !== 'IndexedDB') {
            for (const database of await indexedDB.databases()) {
                await new Promise((resolve, reject) => {
                    const request = indexedDB.deleteDatabase(database.name);
                    request.onsuccess = resolve;
                    request.onerror = () => reject(request.error);
                    request.onblocked = () => reject(new Error('seed database still open'));
                });
            }
        }
    }""", keep)
    assert _has_seed_by_store(context) == {
        store: store == keep for store in ("cookie", "localStorage", "IndexedDB")
    }
    _goto(page, site_url, "v1/cases/ses-01/read.html")
    expect(page.locator('[data-test="session-result"]')).to_have_text("retained")


@pytest.mark.parametrize("relative_path", [
    "v1/cases/col-04/index.html", "v1/cases/col-05/iframe.html",
    "v1/cases/col-05/open-shadow.html", "v1/cases/col-05/closed-shadow.html",
    "v1/cases/ses-01/seed.html", "v1/cases/ses-01/read.html",
])
def test_loading_dynamic_pages_never_submits_a_form(context, site_url, relative_path):
    page = context.new_page()
    submitted = []
    page.on("request", lambda request: submitted.append(request)
            if request.method != "GET" or "unsubmitted" in request.url else None)
    page.add_init_script("""
        window.__testSubmitEvents = 0;
        document.addEventListener('submit', () => window.__testSubmitEvents++, true);
    """)
    _goto(page, site_url, relative_path)
    # Observe after the delayed form and all bounded startup scripts have run.
    page.wait_for_timeout(600)
    assert submitted == []
    assert page.evaluate("window.__testSubmitEvents") == 0
