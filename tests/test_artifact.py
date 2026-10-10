"""The public Pages artifact may contain only static synthetic fixtures."""

import os
from pathlib import Path

import pytest

from isolation_tests.build_pages import build_site
from isolation_tests.fixtures import SAMPLE_BYTES
from isolation_tests.manifest import load_cases
from isolation_tests.publish_guard import assert_artifact_safe, main

REPO_ROOT = Path(__file__).resolve().parents[1]
SHA = "0123456789abcdef0123456789abcdef01234567"
DOT_ENV = "." + "env"


def _site(tmp_path):
    out = tmp_path / "site"
    build_site(load_cases(REPO_ROOT / "tools" / "isolation-tests" / "cases.json"), out, SHA)
    return out


def _put(root, name, content=b"x"):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content if isinstance(content, bytes) else content.encode())
    return path


def test_artifact_refuses_private_config(tmp_path):
    (tmp_path / "config.local.json").write_text("{}")
    with pytest.raises(ValueError, match="private artifact"):
        assert_artifact_safe(tmp_path)


@pytest.mark.parametrize("name", [
    "results/report.json", "evidence/e.json", "run.log", "server.pem", "server.key",
    DOT_ENV, DOT_ENV + ".local", "sub/config.local.json",
])
def test_artifact_refuses_private_names(tmp_path, name):
    _put(tmp_path, "index.html", "<p>ok</p>")
    _put(tmp_path, name, "{}")
    with pytest.raises(ValueError, match="private artifact"):
        assert_artifact_safe(tmp_path)


def test_real_built_site_is_accepted(tmp_path):
    assert assert_artifact_safe(_site(tmp_path)) is None


def test_committed_test_pages_are_accepted():
    assert assert_artifact_safe(REPO_ROOT / "test-pages") is None


def test_missing_or_file_root_is_refused(tmp_path):
    with pytest.raises(ValueError, match="artifact root"):
        assert_artifact_safe(tmp_path / "absent")
    _put(tmp_path, "f.html", "x")
    with pytest.raises(ValueError, match="artifact root"):
        assert_artifact_safe(tmp_path / "f.html")


@pytest.mark.parametrize("name", ["a.py", "a.sh", "a.exe", "a.zip", "a.html.bak", "noext", ".hidden", "a.map"])
def test_unlisted_extensions_are_refused(tmp_path, name):
    _put(tmp_path, name, "x")
    with pytest.raises(ValueError, match="artifact extension"):
        assert_artifact_safe(tmp_path)


@pytest.mark.parametrize("name", ["a.html", "a.css", "a.js", "a.json", "a.svg", "a.png", "a.txt"])
def test_listed_extensions_are_accepted(tmp_path, name):
    _put(tmp_path, name, "plain")
    assert assert_artifact_safe(tmp_path) is None


def test_nojekyll_must_be_empty(tmp_path):
    _put(tmp_path, ".nojekyll", b"")
    assert assert_artifact_safe(tmp_path) is None
    _put(tmp_path, ".nojekyll", b"data")
    with pytest.raises(ValueError, match="artifact extension"):
        assert_artifact_safe(tmp_path)


def test_apk_must_equal_sample_bytes(tmp_path):
    _put(tmp_path, "v1/files/sample.apk", SAMPLE_BYTES)
    assert assert_artifact_safe(tmp_path) is None
    _put(tmp_path, "v1/files/sample.apk", SAMPLE_BYTES + b"x")
    with pytest.raises(ValueError, match="artifact apk"):
        assert_artifact_safe(tmp_path)


def _token(kind):
    return {
        "github": "gh" + "p_" + "A1b2" * 9,
        "pat": "github" + "_pat_" + "A1b2C3d4" * 4,
        "aws": "AK" + "IA" + "ABCDEFGHIJKLMNOP",
        "key": "-----BEGIN " + "RSA PRIVATE KEY-----",
        "bearer": "Authorization: Bearer " + "abcdef0123456789" * 2,
        "slack": "xo" + "xb-" + "1234567890-abcdefghij",
    }[kind]


@pytest.mark.parametrize("kind", ["github", "pat", "aws", "key", "bearer", "slack"])
def test_token_patterns_are_refused_without_echoing_the_value(tmp_path, kind):
    _put(tmp_path, "page.html", f"<p>{_token(kind)}</p>")
    with pytest.raises(ValueError, match="artifact secret") as info:
        assert_artifact_safe(tmp_path)
    assert _token(kind) not in str(info.value)


def test_real_looking_email_is_refused_without_echoing_it(tmp_path):
    address = "someone" + "@" + "mail-provider.net"
    _put(tmp_path, "page.html", f"<p>{address}</p>")
    with pytest.raises(ValueError, match="artifact email") as info:
        assert_artifact_safe(tmp_path)
    assert address not in str(info.value)


@pytest.mark.parametrize("address", ["a@example.com", "b@x.example", "c@host.invalid", "d@users.noreply.github.com"])
def test_reserved_synthetic_email_domains_are_allowed(tmp_path, address):
    _put(tmp_path, "page.html", f"<p>{address}</p>")
    assert assert_artifact_safe(tmp_path) is None


def test_css_at_rules_are_not_emails(tmp_path):
    _put(tmp_path, "a.css", "@media (min-width:1px){a{b:c}} @import 'x';")
    assert assert_artifact_safe(tmp_path) is None


def test_symlink_is_refused(tmp_path):
    target = _put(tmp_path / "outside", "t.html", "x")
    root = tmp_path / "site"
    root.mkdir()
    try:
        os.symlink(target, root / "l.html")
    except (OSError, NotImplementedError):
        pytest.skip("symlink unavailable")
    with pytest.raises(ValueError, match="artifact link"):
        assert_artifact_safe(root)


def test_symlinked_root_is_refused(tmp_path):
    real = tmp_path / "real"
    _put(real, "a.html", "x")
    try:
        os.symlink(real, tmp_path / "link", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink unavailable")
    with pytest.raises(ValueError, match="artifact link"):
        assert_artifact_safe(tmp_path / "link")


def test_hardlink_is_refused(tmp_path):
    root = tmp_path / "site"
    original = _put(tmp_path / "outside", "t.html", "x")
    root.mkdir()
    try:
        os.link(original, root / "h.html")
    except OSError:
        pytest.skip("hardlink unavailable")
    with pytest.raises(ValueError, match="artifact link"):
        assert_artifact_safe(root)


def test_cli_artifact_ok_and_refused_print_status_only(tmp_path, capsys):
    good = tmp_path / "good"
    _put(good, "a.html", "x")
    assert main(["artifact", str(good)]) == 0
    assert "ok" in capsys.readouterr().out
    bad = tmp_path / "bad"
    address = "someone" + "@" + "mail-provider.net"
    _put(bad, "a.html", address)
    assert main(["artifact", str(bad)]) == 1
    out = capsys.readouterr()
    assert address not in out.out + out.err
    assert "refused" in out.out + out.err


def test_build_pages_accepts_commit_option(tmp_path):
    from isolation_tests.build_pages import main as build_main

    out = tmp_path / "o"
    assert build_main(["--manifest", str(REPO_ROOT / "tools/isolation-tests/cases.json"),
                       "--output", str(out), "--commit", SHA]) == 0
    assert assert_artifact_safe(out) is None
