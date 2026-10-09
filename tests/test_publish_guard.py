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
