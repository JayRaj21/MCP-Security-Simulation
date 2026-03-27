#!/usr/bin/env python3
"""
Quick-start launcher for MCP Security Simulation.

Automatically creates a virtual environment, installs dependencies,
and runs the program. No manual setup required.

Usage:
    python3 run.py              # start (security off)
    python3 run.py --security   # start with security already enabled

Use the 'toggle' command inside the session to switch security on/off.
"""
import subprocess
import sys
from pathlib import Path

MIN_PYTHON = (3, 8)

if sys.version_info < MIN_PYTHON:
    sys.exit(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required. You have {sys.version}.")

HERE  = Path(__file__).parent
VENV  = HERE / ".venv"
BIN   = VENV / ("Scripts" if sys.platform == "win32" else "bin")
PIP   = BIN / "pip"
PYTHON = BIN / "python"


def run(*args, **kwargs):
    subprocess.check_call(list(args), **kwargs)


def main():
    # ── Create virtualenv if it doesn't exist ────────────────────────────────
    if not VENV.exists():
        print("Creating virtual environment…")
        run(sys.executable, "-m", "venv", str(VENV))

    # ── Install / update dependencies ────────────────────────────────────────
    print("Checking dependencies…")
    run(str(PIP), "install", "-q", "-r", str(HERE / "requirements.txt"))

    # ── Run the demo, forwarding any CLI arguments ────────────────────────────
    print()
    run(str(PYTHON), str(HERE / "demo.py"), *sys.argv[1:])


if __name__ == "__main__":
    main()
