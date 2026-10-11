"""Optional public HTTPS sample-server base in the catalog."""

import json
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest

ROOT = Path(__file__).resolve().parents[1]
SHA = "d" * 40


def cases():
    from isolation_tests.manifest import load_cases

    return load_cases(ROOT / "tools/isolation-tests/cases.json")


def snapshot(root):
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def test_valid_base_is_emitted_normalized(tmp_path):
    from isolation_tests.build_pages import build_site

    build_site(cases(), tmp_path, SHA, http_base="https://fixture.invalid/proj")
    catalog = json.loads((tmp_path / "catalog.json").read_text(encoding="utf-8"))
    assert catalog["http_base"] == "https://fixture.invalid/proj/"


def test_catalog_without_base_has_no_http_base_key(tmp_path):
    from isolation_tests.build_pages import build_site

    build_site(cases(), tmp_path, SHA)
    assert "http_base" not in json.loads((tmp_path / "catalog.json").read_text(encoding="utf-8"))


BAD = ["http://fixture.invalid/proj/", "https://user:pw@fixture.invalid/", "https://fixture.invalid/a/../b/",
       "https://fixture.invalid/proj/?q=1", "https://fixture.invalid/#f", 5, ""]


@pytest.mark.parametrize("base", BAD)
def test_invalid_base_rejected_at_build_without_writing(tmp_path, base):
    from isolation_tests.build_pages import build_site

    out = tmp_path / "site"
    with pytest.raises(ValueError):
        build_site(cases(), out, SHA, http_base=base)
    assert not out.exists() or snapshot(out) == {}


@pytest.mark.parametrize("base", BAD)
def test_invalid_base_in_existing_catalog_rejected_without_mutation(tmp_path, base):
    from isolation_tests.build_pages import build_site

    build_site(cases(), tmp_path, SHA, http_base="https://fixture.invalid/proj/")
    path = tmp_path / "catalog.json"
    catalog = json.loads(path.read_text(encoding="utf-8"))
    catalog["http_base"] = base
    path.write_text(json.dumps(catalog), encoding="utf-8")
    before = snapshot(tmp_path)
    with pytest.raises(ValueError):
        build_site(cases(), tmp_path, "e" * 40)
    assert snapshot(tmp_path) == before


@pytest.mark.browser
def test_http_fixture_links_become_active_once_base_is_set(browser, tmp_path):
    from isolation_tests.build_pages import build_site

    prefix = "synthetic-project-prefix"
    build_site(cases(), tmp_path / prefix, SHA, http_base="https://fixture.invalid/proj")

    class Quiet(SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Quiet, directory=str(tmp_path)))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    site = f"http://127.0.0.1:{server.server_port}/{prefix}/"
    context = browser.new_context()
    try:
        page = context.new_page()
        page.goto(site)
        page.get_by_role("searchbox").fill("NET-01")
        links = page.locator("a[href]").filter(visible=True).evaluate_all("n => n.map(a => a.href)")
        assert sorted(links) == sorted(
            f"https://fixture.invalid/proj/v1/cases/NET-01/{v}" for v in ("img", "script", "iframe", "fetch"))
        copies = page.get_by_role("button", name="URL 복사").filter(visible=True)
        assert copies.count() == 4 and all(b.is_enabled() for b in copies.all())
        page.get_by_role("searchbox").fill("COL-01")
        page_links = page.locator("a[href]").filter(visible=True).evaluate_all("n => n.map(a => a.href)")
        col = [url for url in page_links if "/col-01/" in url]
        assert col and all(url.startswith(site) for url in col)
    finally:
        context.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
