"""Build public fixtures and a public catalog without publishing test answers."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

from .fixtures import EXTRA_FILES, SAMPLE_BYTES, has_static, render_static
from .manifest import load_cases
from .model import CaseSpec
from .targets import normalize_base


_CASE_ID = re.compile(r"(?:COL|NAV|ANA|NET|SES|DL|HTTP|LIM|HOST|INT|REC)-[0-9]{2}\Z")
_VARIANT = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PUBLIC_CASE_FIELDS = {
    "id", "group", "title", "description", "execution_kind", "target_key",
    "relative_path", "message", "risk_level", "max_requests", "variants",
}
_PUBLIC_GROUPS = (
    "collection", "navigation", "analysis", "network", "session", "download",
    "http", "limits", "host", "integration", "recovery",
)
_DEFAULT_MANIFEST = Path(__file__).resolve().parents[1] / "cases.json"
_DEFAULT_OUTPUT = Path(__file__).resolve().parents[3] / "test-pages"


def _relative(value: str) -> PurePosixPath:
    if (not isinstance(value, str) or not value or "\\" in value or ":" in value
            or any(c.isspace() or ord(c) < 32 for c in value)
            or any(part in {"", ".", ".."} for part in value.split("/"))
            or any(c in value for c in "%?#")):
        raise ValueError("unsafe relative output path")
    path = PurePosixPath(value)
    if path.is_absolute():
        raise ValueError("absolute case output path")
    return path


def _check_path(path: Path) -> None:
    """Reject links (including Windows junctions) in the full lexical path."""
    for component in reversed((path, *path.parents)):
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        if (stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise ValueError("output path contains a symbolic link or junction")
        if component == path and stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise ValueError("managed output is a hard-linked file")


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _matches(pattern: re.Pattern, value: object) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _catalog_files(catalog: object) -> dict[str, str]:
    """Recognize the emitted schema before granting any file ownership."""
    if (not isinstance(catalog, dict)
            or not {"version", "commit_sha", "cases", "files"} <= set(catalog)
            or set(catalog) - {"version", "commit_sha", "cases", "files", "http_base"}
            or type(catalog["version"]) is not int or catalog["version"] != 1
            or not isinstance(catalog["commit_sha"], str)
            or not re.fullmatch(r"[0-9a-fA-F]{40}", catalog["commit_sha"])
            or not isinstance(catalog["cases"], list)
            or not isinstance(catalog["files"], dict)):
        raise ValueError("unrecognized existing catalog")
    if "http_base" in catalog:
        normalize_base(catalog["http_base"])
    for relative, digest in catalog["files"].items():
        _relative(relative)
        if not _matches(_SHA256, digest):
            raise ValueError("invalid catalog file hash")
    recorded = {".nojekyll": _digest(b""), "v1/files/sample.apk": _digest(SAMPLE_BYTES)}
    # Support pages were added after the first release; older catalogs omit them.
    recorded.update({path: _digest(content) for path, content in EXTRA_FILES.items()
                     if path in catalog["files"]})
    seen_ids = set()
    for case in catalog["cases"]:
        if (not isinstance(case, dict) or set(case) != _PUBLIC_CASE_FIELDS
                or not _matches(_CASE_ID, case["id"]) or case["id"] in seen_ids
                or any(not isinstance(case[key], str) for key in ("group", "title", "description", "message"))
                or case["group"] not in _PUBLIC_GROUPS
                or not case["title"].strip() or not case["description"].strip()
                or case["execution_kind"] not in ("page", "http_fixture", "host_probe", "integration")
                or case["risk_level"] not in ("basic", "explicit")
                or type(case["max_requests"]) is not int or case["max_requests"] <= 0
                or (case["target_key"] is not None and not _matches(_NAME, case["target_key"]))
                or not isinstance(case["variants"], list) or not case["variants"]):
            raise ValueError("invalid catalog case record")
        seen_ids.add(case["id"])
        if case["relative_path"] is not None:
            _relative(case["relative_path"])
        folder = f'v1/cases/{case["id"].lower()}'
        if case["execution_kind"] == "page" and case["relative_path"] != f"{folder}/index.html":
            raise ValueError("invalid catalog case path")
        seen_variants = set()
        for variant in case["variants"]:
            if (not isinstance(variant, dict) or set(variant) != {"name", "path", "sha256"}
                    or not _matches(_VARIANT, variant["name"]) or variant["name"] in seen_variants):
                raise ValueError("invalid catalog variant record")
            seen_variants.add(variant["name"])
            path, digest = variant["path"], variant["sha256"]
            if path is None:
                if digest is not None:
                    raise ValueError("unimplemented variant has a recorded hash")
                continue
            _relative(path)
            if (case["execution_kind"] != "page" or path != f'{folder}/{variant["name"]}.html'
                    or not _matches(_SHA256, digest)):
                raise ValueError("invalid catalog variant path or hash")
            recorded[path] = digest
            if len(case["variants"]) == 1:
                recorded[case["relative_path"]] = digest
    if catalog["files"] != recorded:
        raise ValueError("catalog file ownership disagrees with case records")
    return catalog["files"]


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate catalog key")
        result[key] = value
    return result


def build_site(cases: tuple[CaseSpec, ...], output: Path, commit_sha: str,
               http_base: str | None = None) -> dict[str, str]:
    """Plan every write before mutation; preserve all unrelated existing files.

    Catalog version 1 contains only public display metadata, generated byte
    hashes and an optional public HTTPS sample-server base. An unimplemented variant has null path/hash, never a placeholder page.
    The files map covers payloads; the returned map also hashes catalog.json.
    """
    if not isinstance(commit_sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", commit_sha):
        raise ValueError("commit_sha must be a full 40-character Git SHA")
    output = Path(output)
    _check_path(output if output.is_absolute() else Path.cwd() / output)
    output = Path(os.path.abspath(output))
    _check_path(output)
    if output.exists() and not output.is_dir():
        raise ValueError("output must be a directory")
    payloads = {".nojekyll": b"", "v1/files/sample.apk": SAMPLE_BYTES, **EXTRA_FILES}
    public_cases = []
    seen_ids = set()
    for case in cases:
        if not _CASE_ID.fullmatch(case.id) or case.id in seen_ids:
            raise ValueError("invalid or duplicate case id")
        seen_ids.add(case.id)
        if (not case.variants or len(set(case.variants)) != len(case.variants)
                or any(not _VARIANT.fullmatch(name) for name in case.variants)):
            raise ValueError("invalid or duplicate case variant")
        if case.relative_path is not None:
            _relative(case.relative_path)
        if case.execution_kind == "page" and case.relative_path != f"v1/cases/{case.id.lower()}/index.html":
            raise ValueError("static page requires its canonical case path")
        variants = []
        for name in case.variants:
            path = None
            digest = None
            if case.execution_kind == "page" and has_static(case.id, name):
                path = f"v1/cases/{case.id.lower()}/{name}.html"
                content = render_static(case.id, name)
                payloads[path] = content
                digest = _digest(content)
                if len(case.variants) == 1:
                    payloads[case.relative_path] = content
            variants.append({"name": name, "path": path, "sha256": digest})
        public_cases.append({
            "id": case.id, "group": case.group, "title": case.title,
            "description": case.description, "execution_kind": case.execution_kind,
            "target_key": case.target_key, "relative_path": case.relative_path,
            "message": case.message, "risk_level": case.risk_level,
            "max_requests": case.max_requests, "variants": variants,
        })
    hashes = {path: _digest(content) for path, content in sorted(payloads.items())}
    catalog = {"version": 1, "commit_sha": commit_sha, "cases": public_cases, "files": hashes}
    if http_base is not None:
        # Only the public HTTPS sample-server base; never internal targets.
        catalog["http_base"] = normalize_base(http_base)
    payloads["catalog.json"] = _json_bytes(catalog)

    # Read previous ownership only from a recognized catalog; never delete stale
    # files. Refuse to overwrite an arbitrary file even at a planned output path.
    catalog_path = output / "catalog.json"
    _check_path(catalog_path)
    previous_files = {}
    if catalog_path.exists():
        try:
            previous = json.loads(catalog_path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
            previous_files = _catalog_files(previous)
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError) as error:
            raise ValueError("unrecognized existing catalog") from error
    for relative, content in payloads.items():
        path = output.joinpath(*_relative(relative).parts)
        _check_path(path)
        if not path.resolve().is_relative_to(output.resolve()):
            raise ValueError("output path escapes site root")
        if path.exists():
            if not path.is_file():
                raise ValueError("managed output is not a regular file")
            if relative != "catalog.json":
                current = path.read_bytes()
                if current != content and previous_files.get(relative) != _digest(current):
                    raise ValueError("refusing to overwrite an unrelated existing file")
    for relative, content in sorted(payloads.items()):
        path = output.joinpath(*PurePosixPath(relative).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        _check_path(path)
        path.write_bytes(content)
    return {path: _digest(content) for path, content in sorted(payloads.items())}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build public synthetic Pages fixtures")
    parser.add_argument("--manifest", type=Path, default=_DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=_DEFAULT_OUTPUT)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--http-base", default=None, help="public HTTPS sample-server base URL")
    args = parser.parse_args(argv)
    try:
        hashes = build_site(load_cases(args.manifest), args.output, args.commit_sha, args.http_base)
    except (ValueError, OSError) as error:
        parser.exit(2, f"build failed: {error}\n")
    print(f"Built {len(hashes)} public files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
