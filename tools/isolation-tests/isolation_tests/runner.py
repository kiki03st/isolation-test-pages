"""Command-line entry point for the isolation test manifest."""

import argparse
import json
import sys
from pathlib import Path

from .manifest import load_cases


def _host_probe(output: Path, boundary: str | None) -> int:
    from .host_probes import collect_host_facts

    facts = collect_host_facts(boundary=boundary)
    try:
        # Exclusive create: never overwrite an existing evidence file.
        with output.open("x", encoding="utf-8") as handle:
            json.dump({"schema": "host-probe-v1", "facts": facts}, handle,
                      ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
    except OSError:
        print("error: cannot create the output file", file=sys.stderr)
        return 2
    print(f"wrote {len(facts)} facts")
    return 0 if not facts.get("unsupported_boundary") else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="isolation-tests")
    commands = parser.add_subparsers(dest="command", required=True)
    list_command = commands.add_parser("list", help="list cases without executing them")
    list_command.add_argument("--manifest", type=Path, required=True)
    probe = commands.add_parser(
        "host-probe", help="collect host facts; run by the administrator on the inspected host")
    probe.add_argument("--output", type=Path, required=True)
    probe.add_argument("--boundary", choices=("host", "container"))
    arguments = parser.parse_args(argv)
    if arguments.command == "host-probe":
        return _host_probe(arguments.output, arguments.boundary)
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
