"""Validate the personal account boundary and public artifact before publication.

Nothing here prints or returns a real e-mail address, token or remote URL:
failures report only a kind and a count.
"""

import argparse
import json
import re
import stat
import subprocess
import sys
from pathlib import Path

from .fixtures import SAMPLE_BYTES


def assert_personal_target(login: str, owner: str, account_type: str) -> None:
    if account_type != "User" or login != owner:
        raise ValueError("personal owner required")


# --- public artifact -------------------------------------------------------

_ALLOWED_SUFFIXES = {".html", ".css", ".js", ".json", ".svg", ".png", ".txt", ".apk"}
_TEXT_SUFFIXES = {".html", ".css", ".js", ".json", ".svg", ".txt"}
_PRIVATE_DIRS = {"results", "evidence", ".git", ".github", ".venv", "__pycache__"}
_PRIVATE_SUFFIXES = {".log", ".pem", ".key", ".crt", ".p12", ".pfx"}
_PRIVATE_NAMES = {"config.local.json"}
_ENV_PREFIX = "." + "env"
_SECRETS = (
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})")
_SYNTHETIC_DOMAINS = {"example.com", "example.org", "example.net", "users.noreply.github.com"}
_SYNTHETIC_TLDS = {"example", "invalid", "test", "localhost"}


def _is_link(info) -> bool:
    return (stat.S_ISLNK(info.st_mode)
            or bool(getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT))


def _synthetic_domain(domain: str) -> bool:
    domain = domain.lower()
    return domain in _SYNTHETIC_DOMAINS or domain.rsplit(".", 1)[-1] in _SYNTHETIC_TLDS


def _is_private(name: str, suffix: str) -> bool:
    lowered = name.lower()
    return (lowered in _PRIVATE_NAMES or lowered == _ENV_PREFIX
            or lowered.startswith(_ENV_PREFIX + ".") or suffix in _PRIVATE_SUFFIXES)


def _check_file(path: Path, info) -> None:
    name = path.name
    suffix = path.suffix.lower()
    if _is_private(name, suffix):
        raise ValueError("private artifact file present")
    if name == ".nojekyll":
        if info.st_size:
            raise ValueError("artifact extension not allowed")
        return
    if suffix not in _ALLOWED_SUFFIXES or name.startswith("."):
        raise ValueError("artifact extension not allowed")
    content = path.read_bytes()
    if suffix == ".apk":
        if content != SAMPLE_BYTES:
            raise ValueError("artifact apk differs from the sample bytes")
        return
    if suffix not in _TEXT_SUFFIXES:
        return
    text = content.decode("utf-8", errors="replace")
    if any(pattern.search(text) for pattern in _SECRETS):
        raise ValueError("artifact secret pattern found")
    if any(not _synthetic_domain(match.group(1)) for match in _EMAIL.finditer(text)):
        raise ValueError("artifact email address found")


def _walk(directory: Path) -> None:
    for entry in sorted(directory.iterdir(), key=lambda item: item.name):
        info = entry.lstat()
        if _is_link(info):
            raise ValueError("artifact link not allowed")
        if stat.S_ISDIR(info.st_mode):
            if entry.name.lower() in _PRIVATE_DIRS:
                raise ValueError("private artifact directory present")
            _walk(entry)
        elif stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1:
                raise ValueError("artifact link not allowed")
            _check_file(entry, info)
        else:
            raise ValueError("artifact link not allowed")


def assert_artifact_safe(root: Path) -> None:
    root = Path(root)
    try:
        info = root.lstat()
    except OSError:
        raise ValueError("artifact root missing") from None
    if _is_link(info):
        raise ValueError("artifact link not allowed")
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("artifact root is not a directory")
    _walk(root)


# --- repository, remote and history ----------------------------------------

_NOREPLY = re.compile(r"(?:[0-9]+\+)?[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?@users\.noreply\.github\.com\Z")
_WEB_COMMITTER = "noreply@github.com"
_REMOTE = (
    re.compile(r"https://github\.com/(?P<owner>[^/@:\s]+)/(?P<repo>[^/@:\s]+?)(?:\.git)?/?\Z"),
    re.compile(r"git@github\.com:(?P<owner>[^/@:\s]+)/(?P<repo>[^/@:\s]+?)(?:\.git)?\Z"),
    re.compile(r"ssh://git@github\.com/(?P<owner>[^/@:\s]+)/(?P<repo>[^/@:\s]+?)(?:\.git)?/?\Z"),
)


def _run(command: list[str], cwd: Path | None = None) -> str:
    done = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=30, check=False)
    if done.returncode != 0:
        raise RuntimeError("command failed")
    return done.stdout


def _gh_user() -> dict:
    """Read-only identity lookup of the authenticated account."""
    data = json.loads(_run(["gh", "api", "user"]))
    return {"login": data.get("login"), "type": data.get("type")}


def _git_origin(root: Path) -> str | None:
    try:
        return _run(["git", "remote", "get-url", "origin"], cwd=root).strip() or None
    except RuntimeError:
        return None


def _git_history_emails(root: Path) -> list[str]:
    out = _run(["git", "log", "--all", "--format=%ae%n%ce"], cwd=root)
    return out.split("\n")[:-1] if out.endswith("\n") else out.split("\n")


def assert_remote_matches(origin: str | None, owner: str, repo: str) -> None:
    if not origin:
        raise ValueError("remote mismatch")
    for pattern in _REMOTE:
        match = pattern.fullmatch(origin.strip())
        if match:
            if (match["owner"].lower() == owner.lower() and match["repo"].lower() == repo.lower()):
                return
            break
    raise ValueError("remote mismatch")


def assert_history_noreply(emails: list[str]) -> int:
    """Return the number of checked values; refuse any non-noreply address."""
    if not emails:
        raise ValueError("history empty or unreadable")
    bad = sum(1 for value in emails if not (_NOREPLY.fullmatch(value) or value == _WEB_COMMITTER))
    if bad:
        raise ValueError(f"history has {bad} non-noreply author/committer value(s)")
    return len(emails)


def _check_account(owner: str) -> None:
    user = _gh_user()
    assert_personal_target(str(user.get("login")), owner, str(user.get("type")))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="publish_guard", description="Pre-publication safety checks")
    commands = parser.add_subparsers(dest="command", required=True)
    artifact = commands.add_parser("artifact", help="check a static Pages artifact directory")
    artifact.add_argument("root", type=Path)
    history = commands.add_parser("history", help="check every author/committer e-mail is noreply")
    history.add_argument("--repo-root", type=Path, default=Path("."))
    repository = commands.add_parser("repository", help="check account, origin and history")
    repository.add_argument("--owner", required=True)
    repository.add_argument("--repo", required=True)
    repository.add_argument("--repo-root", type=Path, default=Path("."))
    args = parser.parse_args(argv)
    try:
        if args.command == "artifact":
            assert_artifact_safe(args.root)
            print("artifact: ok")
        elif args.command == "history":
            count = assert_history_noreply(_git_history_emails(args.repo_root))
            print(f"history: ok ({count} values checked)")
        else:
            _check_account(args.owner)
            print("account: ok (authenticated User matches owner)")
            assert_remote_matches(_git_origin(args.repo_root), args.owner, args.repo)
            print("remote: ok (origin matches owner/repo)")
            count = assert_history_noreply(_git_history_emails(args.repo_root))
            print(f"history: ok ({count} values checked)")
    except (ValueError, RuntimeError, OSError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        kind = str(error) if isinstance(error, ValueError) else "check could not complete"
        print(f"{args.command}: refused - {kind}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
