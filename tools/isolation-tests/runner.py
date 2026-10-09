"""Compatibility entry point for direct execution of the packaged CLI."""

from isolation_tests.runner import main


if __name__ == "__main__":
    raise SystemExit(main())
