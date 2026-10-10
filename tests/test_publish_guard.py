"""Publishing is permitted only to the authenticated personal owner."""

import pytest


def test_matching_personal_owner_is_accepted():
    from isolation_tests.publish_guard import assert_personal_target

    assert assert_personal_target("personal-user", "personal-user", "User") is None


@pytest.mark.parametrize(
    ("login", "owner", "account_type"),
    [
        ("personal-user", "organization", "Organization"),
        ("organization", "organization", "Organization"),
        ("personal-user", "another-user", "User"),
        ("personal-user", "personal-user", "Bot"),
    ],
)
def test_personal_owner_guard_rejects_non_personal_target(login, owner, account_type):
    from isolation_tests.publish_guard import assert_personal_target

    with pytest.raises(ValueError, match="personal owner"):
        assert_personal_target(login, owner, account_type)


# --- repository / history guard (gh and git are replaced by fakes; no network) ---

NOREPLY = "102171184+personal-user@users.noreply.github.com"


@pytest.fixture
def fake_env(monkeypatch):
    from isolation_tests import publish_guard as guard

    state = {
        "user": {"login": "personal-user", "type": "User"},
        "origin": "https://github.com/personal-user/isolation-test-pages.git",
        "emails": [NOREPLY, NOREPLY, "noreply@github.com"],
    }
    monkeypatch.setattr(guard, "_gh_user", lambda: state["user"])
    monkeypatch.setattr(guard, "_git_origin", lambda root: state["origin"])
    monkeypatch.setattr(guard, "_git_history_emails", lambda root: state["emails"])
    return state


def _repo(argv=("repository", "--owner", "personal-user", "--repo", "isolation-test-pages")):
    from isolation_tests.publish_guard import main

    return main(list(argv))


def test_repository_guard_accepts_matching_personal_setup(fake_env, capsys):
    assert _repo() == 0
    assert "ok" in capsys.readouterr().out


@pytest.mark.parametrize("user", [
    {"login": "personal-user", "type": "Organization"},
    {"login": "other-user", "type": "User"},
    {"login": "personal-user", "type": "Bot"},
])
def test_repository_guard_rejects_wrong_account(fake_env, user, capsys):
    fake_env["user"] = user
    assert _repo() == 1
    assert "refused" in capsys.readouterr().out


def test_repository_guard_rejects_owner_that_is_not_the_login(fake_env):
    assert _repo(("repository", "--owner", "an-org", "--repo", "isolation-test-pages")) == 1


@pytest.mark.parametrize("origin", [
    "https://github.com/an-org/isolation-test-pages.git",
    "https://github.com/personal-user/other-repo",
    "https://github.com/personal-user/isolation-test-pages-extra",
    "git@github.com:an-org/isolation-test-pages.git",
    "https://example.org/personal-user/isolation-test-pages",
    "https://user:" + "tok" + "en@github.com/personal-user/isolation-test-pages",
    "",
    None,
])
def test_repository_guard_rejects_remote_mismatch(fake_env, origin):
    fake_env["origin"] = origin
    assert _repo() == 1


@pytest.mark.parametrize("origin", [
    "https://github.com/personal-user/isolation-test-pages",
    "https://github.com/Personal-User/isolation-test-pages.git",
    "git@github.com:personal-user/isolation-test-pages.git",
    "ssh://git@github.com/personal-user/isolation-test-pages.git",
])
def test_repository_guard_accepts_equivalent_remote_forms(fake_env, origin):
    fake_env["origin"] = origin
    assert _repo() == 0


@pytest.mark.parametrize("emails", [
    ["real" + "@" + "mail-provider.net"],
    [NOREPLY, "someone" + "@" + "org.example.org"],
    [NOREPLY, ""],
    ["x" + "@" + "users.noreply.github.com.evil.net"],
])
def test_history_with_non_noreply_email_is_rejected_without_echo(fake_env, emails, capsys):
    fake_env["emails"] = emails
    assert _repo() == 1
    out = capsys.readouterr()
    for value in emails:
        if value:
            assert value not in out.out + out.err
    assert "history" in out.out + out.err


def test_empty_history_is_rejected(fake_env):
    fake_env["emails"] = []
    assert _repo() == 1


def test_history_subcommand_runs_without_account_lookup(fake_env, monkeypatch):
    from isolation_tests import publish_guard as guard

    def boom():
        raise AssertionError("no network")

    monkeypatch.setattr(guard, "_gh_user", boom)
    assert guard.main(["history"]) == 0
    fake_env["emails"] = ["real" + "@" + "mail-provider.net"]
    assert guard.main(["history"]) == 1


def test_gh_failure_is_a_refusal_not_a_traceback(fake_env, monkeypatch, capsys):
    from isolation_tests import publish_guard as guard

    def fail():
        raise RuntimeError("gh unavailable")

    monkeypatch.setattr(guard, "_gh_user", fail)
    assert _repo() == 1
    assert "refused" in capsys.readouterr().out
