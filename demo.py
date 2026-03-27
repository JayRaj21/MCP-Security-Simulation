"""
MCP Security Simulation — Entry Point

Usage:
    python demo.py              # start (security off by default)
    python demo.py --security   # start with security already enabled

Use the 'toggle' command inside the session to switch security on or off
at any time without restarting.
"""
import argparse

from file_agent import restore_test_files, run_interactive


def main() -> None:
    parser = argparse.ArgumentParser(
        description="MCP Security Simulation — interactive file integrity demo",
        epilog="Use the 'toggle' command inside the session to switch security on/off.",
    )
    parser.add_argument(
        "--security",
        action="store_true",
        help="Start with HMAC-SHA256 file protection already enabled",
    )
    args = parser.parse_args()

    restore_test_files(security_enabled=args.security)
    run_interactive(security_enabled=args.security)


if __name__ == "__main__":
    main()
