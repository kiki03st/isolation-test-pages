"""Compatibility entry point for direct execution of the fixture server."""

from isolation_tests.fixture_server import main


if __name__ == "__main__":
    raise SystemExit(main())
