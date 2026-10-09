"""Public byte, DOM, and safe-output contracts for the static Pages builder."""

import hashlib
import json
from dataclasses import replace
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import pytest

from isolation_tests.model import CaseSpec


COMMIT_SHA = "a" * 40
SAMPLE_BYTES = b"ISOLATION TEST ONLY - NON EXECUTABLE SAMPLE\n"
STATIC_VARIANTS = (
    ("COL-01", "default"),
    ("COL-02", "default"),
    ("COL-03", "default"),
    ("ANA-01", "default"),
    ("ANA-02", "default"),
    ("ANA-03", "password"),
    ("ANA-03", "otp"),
    ("ANA-04", "default"),
    ("ANA-05", "default"),
    ("ANA-06", "warning"),
    ("ANA-06", "negation"),
    ("ANA-06", "quotation"),
    ("ANA-07", "baseline"),
    ("ANA-07", "injection"),
    ("DL-01", "default"),
)


def make_case(case_id="COL-01", variants=("default",)):
    """Use the shared public type, without waiting for the manifest task."""
    return CaseSpec(
        id=case_id,
        group="collection" if case_id.startswith("COL") else "analysis",
        title="합성 표본",
        description="catalog-only-description-marker",
        execution_kind="page",
        target_key="pages",
        relative_path=f"v1/cases/{case_id.lower()}/index.html",
        variants=variants,
        required_capabilities=("collector",),
        message="",
        expected_observations={"assertions": {"required_text": ["answer-only-marker"]}},
        expected_analysis={"final_state": "smishing_suspected"},
        required_evidence=("collection",),
        risk_level="basic",
        max_requests=1,
        recovery_case=None,
    )


class Document(HTMLParser):
    """Read observable attributes and ancestry without assuming HTML formatting."""

    VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self, html):
        super().__init__(convert_charrefs=True)
        self.elements = []
        self.stack = []
        self.text = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        element = (tag, dict(attrs), tuple(self.stack))
        self.elements.append(element)
        if tag not in self.VOID_TAGS:
            self.stack.append((tag, dict(attrs)))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in self.VOID_TAGS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break

    def handle_data(self, data):
        self.text.append(data)

    def find(self, tag):
        return [(attrs, ancestors) for name, attrs, ancestors in self.elements if name == tag]


def render_document(case_id, variant="default"):
    from isolation_tests.fixtures import render_static

    return Document(render_static(case_id, variant).decode("utf-8"))


def json_atoms(value):
    """Catalog layout is intentionally unspecified; inspect JSON keys and values."""
    if isinstance(value, dict):
        return set(value).union(*(json_atoms(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(json_atoms(item) for item in value))
    return {value} if isinstance(value, str) else set()


@pytest.mark.parametrize("case_id,variant", STATIC_VARIANTS)
def test_static_bytes_are_deterministic_utf8_without_answer_metadata(case_id, variant):
    from isolation_tests.fixtures import render_static

    first = render_static(case_id, variant)
    assert isinstance(first, bytes)
    assert first == render_static(case_id, variant)
    html = first.decode("utf-8")
    document = Document(html)
    assert document.find("html")
    assert any(attrs.get("charset", "").lower() == "utf-8" for attrs, _ in document.find("meta"))
    assert any("가" <= character <= "힣" for character in "".join(document.text))
    for answer in ("expected_analysis", "expected_observations", "smishing_suspected", "answer-only-marker"):
        assert answer not in html


def test_col01_preserves_reference_title_table_korean_and_emoji():
    document = render_document("COL-01")
    text = "".join(document.text)
    assert "수집 기준" in text
    assert "배송 상태: 배송 중" in text
    assert document.find("table")
    assert any(ord(character) > 0xFFFF for character in text)
    assert not document.find("input")


def test_col02_exposes_actual_label_aria_fieldset_and_external_form_relationships():
    document = render_document("COL-02")
    ids = {attrs["id"] for _, attrs, _ in document.elements if attrs.get("id")}
    inputs = document.find("input")
    labels = document.find("label")
    assert any(attrs.get("for") in {field.get("id") for field, _ in inputs} for attrs, _ in labels)
    for relationship in ("aria-labelledby", "aria-describedby"):
        references = [attrs[relationship].split() for _, attrs, _ in document.elements if attrs.get(relationship)]
        assert references
        assert all(reference in ids for group in references for reference in group)
    assert any("disabled" in attrs for attrs, _ in inputs)
    assert any("readonly" in attrs for attrs, _ in inputs)
    assert document.find("fieldset") and document.find("legend")
    form_ids = {attrs["id"] for attrs, _ in document.find("form") if attrs.get("id")}
    assert any(
        attrs.get("form") in form_ids and not any(tag == "form" for tag, _ in ancestors)
        for attrs, ancestors in inputs
    )


@pytest.mark.parametrize("repository", ["isolation-test-pages", "renamed-project"])
@pytest.mark.parametrize("filename", ["index.html", "default.html", ""])
def test_col03_relative_base_links_and_form_destinations_stay_in_pages_project(repository, filename):
    document = render_document("COL-03")
    bases = document.find("base")
    assert len(bases) == 1
    base_href = bases[0][0]["href"]
    assert base_href and not urlsplit(base_href).scheme and not base_href.startswith("/")
    document_url = f"https://fixture.invalid/{repository}/v1/cases/col-03/{filename}"
    base_url = urljoin(document_url, base_href)
    assert urlsplit(base_url).netloc == "fixture.invalid"
    assert urlsplit(base_url).path.startswith(f"/{repository}/")
    references = []
    for tag, attribute in (("a", "href"), ("form", "action"), ("button", "formaction")):
        values = [attrs[attribute] for attrs, _ in document.find(tag) if attrs.get(attribute)]
        assert values, f"COL-03 lacks a real {tag}[{attribute}]"
        references.extend(values)
    for reference in references:
        assert not urlsplit(reference).scheme and not reference.startswith("/")
        destination = urlsplit(urljoin(base_url, reference))
        assert destination.netloc == "fixture.invalid"
        assert destination.path.startswith(f"/{repository}/")


@pytest.mark.parametrize("variant,field_type,label", [("password", "password", "비밀번호"), ("otp", None, "인증번호")])
def test_ana03_has_the_actual_requested_credential_form(variant, field_type, label):
    document = render_document("ANA-03", variant)
    assert label in "".join(document.text)
    assert document.find("form") and document.find("input")
    if field_type is not None:
        assert any(attrs.get("type") == field_type for attrs, _ in document.find("input"))


def test_ana01_shows_query_result_without_invented_credential_inputs():
    document = render_document("ANA-01")
    assert "배송" in "".join(document.text)
    assert not document.find("input")
    assert not any(attrs.get("href", "").endswith(".apk") for attrs, _ in document.find("a"))


def test_ana02_has_address_correction_reason_and_form():
    document = render_document("ANA-02")
    text = "".join(document.text)
    assert "주소" in text and "수정" in text
    assert document.find("form") and document.find("input")
    assert not any(attrs.get("type") == "password" for attrs, _ in document.find("input"))


def test_ana05_exposes_redelivery_fee_and_payment_request():
    document = render_document("ANA-05")
    text = "".join(document.text)
    assert "재배송" in text and "1,000" in text and "결제" in text


@pytest.mark.parametrize("variant", ["warning", "negation", "quotation"])
def test_ana06_contexts_do_not_turn_mentions_into_credential_or_install_requests(variant):
    document = render_document("ANA-06", variant)
    text = "".join(document.text)
    assert "설치" in text or "인증번호" in text
    assert not document.find("input")
    assert not any(attrs.get("href", "").endswith(".apk") for attrs, _ in document.find("a"))


def test_ana07_injection_preserves_baseline_request_and_form_structure():
    baseline = render_document("ANA-07", "baseline")
    injection = render_document("ANA-07", "injection")
    baseline_text = " ".join("".join(baseline.text).split())
    injection_text = " ".join("".join(injection.text).split())
    assert baseline_text != injection_text
    # Added instructions may occur anywhere, while original content keeps its order.
    remaining_words = iter(injection_text.split())
    assert all(any(word == original for word in remaining_words) for original in baseline_text.split())
    for tag in ("form", "label", "input", "button"):
        baseline_elements = [attrs for attrs, _ in baseline.find(tag)]
        assert baseline_elements, f"baseline must contain observable {tag} elements"
        assert baseline_elements == [attrs for attrs, _ in injection.find(tag)]


@pytest.mark.parametrize("case_id,variant", STATIC_VARIANTS)
def test_static_fixtures_do_not_automatically_submit_or_execute_files(case_id, variant):
    document = render_document(case_id, variant)
    assert not document.find("script")
    for _, attrs, _ in document.elements:
        assert not any(name.startswith("on") for name in attrs)
        assert not any(str(value).lower().startswith("javascript:") for value in attrs.values())


@pytest.mark.parametrize("case_id", ["ANA-04", "DL-01"])
def test_download_link_resolves_to_the_project_dummy_file(case_id):
    document = render_document(case_id)
    document_url = f"https://fixture.invalid/renamed-project/v1/cases/{case_id.lower()}/index.html"
    links = [attrs["href"] for attrs, _ in document.find("a") if attrs.get("href", "").endswith("sample.apk")]
    assert links
    assert {urljoin(document_url, link) for link in links} == {"https://fixture.invalid/renamed-project/v1/files/sample.apk"}
    if case_id == "ANA-04":
        assert "설치" in "".join(document.text)


@pytest.mark.parametrize("case_id,variant", [("UNKNOWN-01", "default"), ("COL-01", "unknown"), ("COL-01", "../escape")])
def test_renderer_rejects_unregistered_cases_and_variants(case_id, variant):
    from isolation_tests.fixtures import render_static

    with pytest.raises(ValueError):
        render_static(case_id, variant)


def test_build_site_returns_actual_sha256_and_is_stable_across_output_directories(tmp_path):
    from isolation_tests.build_pages import build_site

    cases = (make_case(), make_case("ANA-03", ("password", "otp")), make_case("DL-01"))
    first_output, second_output = tmp_path / "first", tmp_path / "second"
    first = build_site(cases, first_output, COMMIT_SHA)
    second = build_site(cases, second_output, COMMIT_SHA)
    assert first == second
    assert isinstance(first, dict)
    required_paths = {
        ".nojekyll", "catalog.json", "v1/files/sample.apk",
        "v1/cases/col-01/default.html", "v1/cases/col-01/index.html",
        "v1/cases/ana-03/password.html", "v1/cases/ana-03/otp.html",
        "v1/cases/dl-01/index.html",
    }
    assert required_paths <= first.keys()
    actual_files = {path.relative_to(first_output).as_posix() for path in first_output.rglob("*") if path.is_file()}
    assert actual_files == set(first)
    for relative_path, digest in first.items():
        path = Path(relative_path)
        assert not path.is_absolute() and ".." not in path.parts
        assert digest == hashlib.sha256((first_output / path).read_bytes()).hexdigest()
        assert (first_output / path).read_bytes() == (second_output / path).read_bytes()
    assert "수집 기준" in (first_output / "v1/cases/col-01/index.html").read_text(encoding="utf-8")


def test_single_nondefault_variant_has_identical_index_alias(tmp_path):
    from isolation_tests.build_pages import build_site

    output = tmp_path / "site"
    hashes = build_site((make_case("ANA-03", ("password",)),), output, COMMIT_SHA)
    index_path = "v1/cases/ana-03/index.html"
    variant_path = "v1/cases/ana-03/password.html"
    assert (output / index_path).read_bytes() == (output / variant_path).read_bytes()
    assert hashes[index_path] == hashes[variant_path]


def test_catalog_contains_commit_case_variants_and_their_actual_hashes(tmp_path):
    from isolation_tests.build_pages import build_site

    output = tmp_path / "site"
    build_site((make_case("ANA-03", ("password", "otp")),), output, COMMIT_SHA)
    catalog = json.loads((output / "catalog.json").read_text(encoding="utf-8"))
    atoms = json_atoms(catalog)
    assert {COMMIT_SHA, "ANA-03", "password", "otp"} <= atoms
    for variant in ("password", "otp"):
        page = output / f"v1/cases/ana-03/{variant}.html"
        assert hashlib.sha256(page.read_bytes()).hexdigest() in atoms
    assert not {"expected_analysis", "expected_observations"} & atoms


def test_build_never_embeds_expected_answers_or_environment_secret_in_case_html(tmp_path, monkeypatch):
    from isolation_tests.build_pages import build_site

    secret = "synthetic-token-value-never-publish-937"
    monkeypatch.setenv("ISOLATION_TEST_TOKEN", secret)
    output = tmp_path / "site"
    build_site((make_case(),), output, COMMIT_SHA)
    for path in output.rglob("*"):
        if path.is_file():
            assert secret.encode() not in path.read_bytes()
    for path in (output / "v1/cases").rglob("*.html"):
        html = path.read_text(encoding="utf-8")
        for marker in ("catalog-only-description-marker", "answer-only-marker", "smishing_suspected", "expected_analysis", "expected_observations"):
            assert marker not in html


def test_dummy_apk_contains_only_the_exact_nonexecutable_sample_bytes(tmp_path):
    from isolation_tests.build_pages import build_site

    output = tmp_path / "site"
    build_site((make_case("DL-01"),), output, COMMIT_SHA)
    assert (output / "v1/files/sample.apk").read_bytes() == SAMPLE_BYTES


def test_rebuild_preserves_unrelated_files_and_updates_managed_catalog(tmp_path):
    from isolation_tests.build_pages import build_site

    output = tmp_path / "site"
    output.mkdir()
    unrelated = output / "keep-personal-notes.txt"
    unrelated.write_bytes(b"never delete or overwrite\n")
    build_site((make_case(),), output, COMMIT_SHA)
    second_sha = "b" * 40
    build_site((make_case(),), output, second_sha)
    assert unrelated.read_bytes() == b"never delete or overwrite\n"
    assert second_sha in json_atoms(json.loads((output / "catalog.json").read_text(encoding="utf-8")))


@pytest.mark.parametrize("bad_path", ["../outside.html", "v1/cases/../../../../outside.html", r"..\outside.html"])
def test_builder_rejects_relative_output_path_escape(tmp_path, bad_path):
    from isolation_tests.build_pages import build_site

    outside = tmp_path / "outside.html"
    outside.write_bytes(b"outside must remain unchanged")
    case = replace(make_case(), relative_path=bad_path)
    with pytest.raises(ValueError):
        build_site((case,), tmp_path / "site", COMMIT_SHA)
    assert outside.read_bytes() == b"outside must remain unchanged"


def test_builder_rejects_absolute_case_output_path(tmp_path):
    from isolation_tests.build_pages import build_site

    outside = tmp_path / "outside.html"
    outside.write_bytes(b"outside must remain unchanged")
    case = replace(make_case(), relative_path=str(outside))
    with pytest.raises(ValueError):
        build_site((case,), tmp_path / "site", COMMIT_SHA)
    assert outside.read_bytes() == b"outside must remain unchanged"


@pytest.mark.parametrize("link_location", ["output", "ancestor", "subdirectory", "file"])
def test_builder_rejects_symlinks_without_mutating_their_destination(tmp_path, link_location):
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "index.html"
    sentinel.write_bytes(b"symlink destination must remain unchanged")
    output = tmp_path / "site"
    if link_location == "output":
        link, destination = output, outside
    elif link_location == "ancestor":
        link, destination = tmp_path / "linked-parent", outside
        output = link / "site"
    elif link_location == "subdirectory":
        output.mkdir()
        link, destination = output / "v1", outside
    else:
        folder = output / "v1/cases/col-01"
        folder.mkdir(parents=True)
        link, destination = folder / "index.html", sentinel
    try:
        link.symlink_to(destination, target_is_directory=destination.is_dir())
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"OS symlink creation unavailable: {error}")
    from isolation_tests.build_pages import build_site

    with pytest.raises(ValueError):
        build_site((make_case(),), output, COMMIT_SHA)
    assert sentinel.read_bytes() == b"symlink destination must remain unchanged"
    assert sorted(path.relative_to(outside).as_posix() for path in outside.rglob("*")) == ["index.html"]


def test_manifest_static_observable_contracts_match_the_rendered_fixtures():
    from isolation_tests.manifest import load_cases

    manifest = Path(__file__).resolve().parents[1] / "tools/isolation-tests/cases.json"
    cases = {case.id: case for case in load_cases(manifest)}
    for case_id, variant in STATIC_VARIANTS:
        document = render_document(case_id, variant)
        assertions = cases[case_id].expected_observations["variants"][variant]["assertions"]
        text = "".join(document.text)
        for required in assertions.get("required_text", []):
            assert required in text
        for forbidden in assertions.get("forbidden_text", []):
            assert forbidden not in text
        if "title" in assertions:
            assert assertions["title"] in text


def test_full_manifest_catalogs_all_variants_without_private_contracts(tmp_path):
    from isolation_tests.build_pages import build_site
    from isolation_tests.manifest import load_cases

    manifest = Path(__file__).resolve().parents[1] / "tools/isolation-tests/cases.json"
    cases = load_cases(manifest)
    output = tmp_path / "site"
    hashes = build_site(cases, output, COMMIT_SHA)
    catalog = json.loads((output / "catalog.json").read_text(encoding="utf-8"))
    assert len(catalog["cases"]) == 43
    assert sum(len(case["variants"]) for case in catalog["cases"]) == 96
    assert not {"expected_observations", "expected_analysis", "required_evidence", "required_facts", "final_state", "required_signal_codes"} & json_atoms(catalog)
    for case in catalog["cases"]:
        for variant in case["variants"]:
            if variant["path"] is not None:
                assert hashes[variant["path"]] == variant["sha256"]
            else:
                assert variant["sha256"] is None


def test_existing_unrelated_file_at_a_generated_path_is_preserved(tmp_path):
    from isolation_tests.build_pages import build_site

    output = tmp_path / "site"
    conflicting = output / "v1/cases/col-01/index.html"
    conflicting.parent.mkdir(parents=True)
    conflicting.write_bytes(b"personal file at a future generated path")
    with pytest.raises(ValueError):
        build_site((make_case(),), output, COMMIT_SHA)
    assert conflicting.read_bytes() == b"personal file at a future generated path"
    assert not (output / "catalog.json").exists()


def test_late_invalid_case_is_rejected_before_any_site_write(tmp_path):
    from isolation_tests.build_pages import build_site

    output = tmp_path / "site"
    with pytest.raises(ValueError):
        build_site((make_case(), replace(make_case("ANA-01"), relative_path="../escape.html")), output, COMMIT_SHA)
    assert not output.exists()


def test_builder_rejects_windows_junction_ancestor_without_writes(tmp_path):
    import subprocess
    import sys

    if sys.platform != "win32":
        pytest.skip("Windows junction contract")
    outside = tmp_path / "outside"
    outside.mkdir()
    junction = tmp_path / "linked-parent"
    result = subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(outside)], capture_output=True)
    if result.returncode:
        pytest.skip("OS junction creation unavailable")
    from isolation_tests.build_pages import build_site

    with pytest.raises(ValueError):
        build_site((make_case(),), junction / "site", COMMIT_SHA)
    assert not list(outside.iterdir())


def test_build_main_generates_all_current_static_files_and_reports_bad_sha(tmp_path):
    from isolation_tests.build_pages import main

    output = tmp_path / "site"
    assert main(["--output", str(output), "--commit-sha", COMMIT_SHA]) == 0
    assert (output / "v1/cases/col-01/index.html").exists()
    assert (output / "v1/files/sample.apk").read_bytes() == SAMPLE_BYTES
    with pytest.raises(SystemExit) as error:
        main(["--output", str(output), "--commit-sha", "invalid"])
    assert error.value.code == 2


def test_managed_output_hardlink_cannot_mutate_an_external_file(tmp_path):
    import os

    from isolation_tests.build_pages import build_site

    output = tmp_path / "site"
    build_site((make_case(),), output, COMMIT_SHA)
    outside = tmp_path / "external-catalog.json"
    try:
        os.link(output / "catalog.json", outside)
    except OSError as error:
        pytest.skip(f"OS hardlink creation unavailable: {error}")
    original = outside.read_bytes()
    with pytest.raises(ValueError):
        build_site((make_case(),), output, "b" * 40)
    assert outside.read_bytes() == original


def test_unrelated_catalog_with_similar_top_level_keys_preserves_the_entire_site(tmp_path):
    from isolation_tests.build_pages import build_site

    output = tmp_path / "site"
    output.mkdir()
    sentinel_catalog = b'{"version":1,"commit_sha":"personal notes","cases":"unrelated catalog","files":{}}'
    (output / "catalog.json").write_bytes(sentinel_catalog)
    (output / "notes.txt").write_bytes(b"personal notes must remain")
    before = {path.relative_to(output).as_posix(): path.read_bytes() for path in output.rglob("*") if path.is_file()}
    with pytest.raises(ValueError):
        build_site((make_case(),), output, COMMIT_SHA)
    after = {path.relative_to(output).as_posix(): path.read_bytes() for path in output.rglob("*") if path.is_file()}
    assert before == after


@pytest.mark.parametrize("malformation", [
    "sha", "boolean-version", "case-list", "case-fields", "case-id", "case-group", "variant-fields",
    "variant-name", "variant-path", "variant-hash", "null-hash", "file-traversal",
    "file-hash", "extra-ownership", "missing-file", "alias-hash", "duplicate-case",
])
def test_malformed_catalog_cannot_grant_file_ownership_or_mutate_site(tmp_path, malformation):
    from isolation_tests.build_pages import build_site

    output = tmp_path / "site"
    build_site((make_case(),), output, COMMIT_SHA)
    catalog_path = output / "catalog.json"
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    case = catalog["cases"][0]
    variant = case["variants"][0]
    if malformation == "sha":
        catalog["commit_sha"] = "notes"
    elif malformation == "boolean-version":
        catalog["version"] = True
    elif malformation == "case-list":
        catalog["cases"] = "unrelated"
    elif malformation == "case-fields":
        case.pop("title")
    elif malformation == "case-id":
        case["id"] = "../personal"
    elif malformation == "case-group":
        case["group"] = "personal_notes"
    elif malformation == "variant-fields":
        variant["notes"] = "personal"
    elif malformation == "variant-name":
        variant["name"] = "../personal"
    elif malformation == "variant-path":
        variant["path"] = "../personal.html"
    elif malformation == "variant-hash":
        variant["sha256"] = "0" * 64
    elif malformation == "null-hash":
        variant["sha256"] = None
    elif malformation == "file-traversal":
        catalog["files"]["../personal.html"] = "0" * 64
    elif malformation == "file-hash":
        catalog["files"][variant["path"]] = "notes"
    elif malformation == "extra-ownership":
        catalog["files"]["notes.txt"] = hashlib.sha256(b"personal notes must remain").hexdigest()
    elif malformation == "missing-file":
        catalog["files"].pop(variant["path"])
    elif malformation == "alias-hash":
        catalog["files"][case["relative_path"]] = "0" * 64
    else:
        catalog["cases"].append(case.copy())
    catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
    (output / "notes.txt").write_bytes(b"personal notes must remain")
    before = {path.relative_to(output).as_posix(): path.read_bytes() for path in output.rglob("*") if path.is_file()}
    with pytest.raises(ValueError):
        build_site((make_case(),), output, "b" * 40)
    after = {path.relative_to(output).as_posix(): path.read_bytes() for path in output.rglob("*") if path.is_file()}
    assert before == after


def test_recognized_full_manifest_catalog_allows_a_sha_rebuild(tmp_path):
    from isolation_tests.build_pages import build_site
    from isolation_tests.manifest import load_cases

    cases = load_cases(Path(__file__).resolve().parents[1] / "tools/isolation-tests/cases.json")
    output = tmp_path / "site"
    first = build_site(cases, output, COMMIT_SHA)
    second = build_site(cases, output, "b" * 40)
    assert first.keys() == second.keys()
    assert all(first[path] == second[path] for path in first if path != "catalog.json")
    assert first["catalog.json"] != second["catalog.json"]
    assert json.loads((output / "catalog.json").read_text(encoding="utf-8"))["commit_sha"] == "b" * 40


def test_duplicate_catalog_keys_are_rejected_without_changing_any_files(tmp_path):
    from isolation_tests.build_pages import build_site

    output = tmp_path / "site"
    build_site((make_case(),), output, COMMIT_SHA)
    catalog_path = output / "catalog.json"
    original = catalog_path.read_text(encoding="utf-8")
    catalog_path.write_text(original.replace('"version": 1', '"version": 0, "version": 1'), encoding="utf-8")
    before = {path.relative_to(output).as_posix(): path.read_bytes() for path in output.rglob("*") if path.is_file()}
    with pytest.raises(ValueError):
        build_site((make_case(),), output, "b" * 40)
    after = {path.relative_to(output).as_posix(): path.read_bytes() for path in output.rglob("*") if path.is_file()}
    assert before == after
