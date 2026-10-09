"""Command-line entry point for the isolation test manifest."""

import argparse
import sys
from pathlib import Path

from .manifest import load_cases


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="isolation-tests")
    commands = parser.add_subparsers(dest="command", required=True)
    list_command = commands.add_parser("list", help="list cases without executing them")
    list_command.add_argument("--manifest", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        cases = load_cases(arguments.manifest)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for case in cases:
        print(f"{case.id}\t{case.group}\t{case.execution_kind}\t{case.title}\t{','.join(case.variants)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
