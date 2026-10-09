"""Validate the personal account boundary before publication."""


def assert_personal_target(login: str, owner: str, account_type: str) -> None:
    if account_type != "User" or login != owner:
        raise ValueError("personal owner required")
