#!/usr/bin/env python3
"""Quick-start launcher for MCP Security Simulation v2.

Usage
-----
    python run_v2.py                # HTTP mode  (default, good for demos)
    python run_v2.py --stdio        # stdio mode (for Claude Desktop / MCP clients)
    python run_v2.py --port 9000    # custom port

Environment variables (all optional)
-------------------------------------
    GITHUB_REPO          public GitHub repo to browse (default: public-apis/public-apis)
    GITHUB_BRANCH        branch name (default: master)
    GITHUB_TOKEN         personal access token to raise API rate limits
    MCP_ENCRYPTION_KEY   AES-256 key string (default: demo value — change in production)
    ADMIN_PASSWORD       admin user password (default: admin123)
    VIEWER_PASSWORD      viewer user password (default: view456)
    SESSION_DURATION_SECONDS  session lifetime in seconds (default: 3600)
"""
import argparse
import subprocess
import sys
import os


MIN_PYTHON = (3, 10)

def check_python():
    if sys.version_info < MIN_PYTHON:
        sys.exit(
            f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ required "
            f"(found {sys.version_info.major}.{sys.version_info.minor})"
        )


def _ensure_venv() -> str:
    """Create .venv if it doesn't exist and return the path to its Python binary."""
    venv_dir = os.path.join(os.path.dirname(__file__), ".venv")
    if sys.platform == "win32":
        venv_python = os.path.join(venv_dir, "Scripts", "python.exe")
    else:
        venv_python = os.path.join(venv_dir, "bin", "python")

    if not os.path.isfile(venv_python):
        print("[v2] Creating virtual environment …")
        subprocess.check_call([sys.executable, "-m", "venv", venv_dir])
    return venv_python


def install_deps():
    venv_python = _ensure_venv()
    req = os.path.join(os.path.dirname(__file__), "v2", "requirements.txt")
    print("[v2] Installing / verifying dependencies …")
    subprocess.check_call(
        [venv_python, "-m", "pip", "install", "-r", req, "-q"],
        stdout=subprocess.DEVNULL,
    )
    print("[v2] Dependencies ready.")
    # Re-exec under the venv Python so imported packages are available
    if os.path.abspath(sys.executable) != os.path.abspath(venv_python):
        os.execv(venv_python, [venv_python] + sys.argv)


def main():
    check_python()

    parser = argparse.ArgumentParser(
        description="MCP Security Simulation v2 launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--stdio",
        action="store_true",
        help="Use stdio transport instead of HTTP (for Claude Desktop / MCP clients)",
    )
    parser.add_argument("--host", default="127.0.0.1", help="HTTP bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="HTTP port (default: 8000)")
    parser.add_argument(
        "--skip-install",
        action="store_true",
        help="Skip dependency installation check",
    )
    args = parser.parse_args()

    if not args.skip_install:
        install_deps()

    cmd = [sys.executable, "v2/server.py"]
    if args.stdio:
        cmd += ["--transport", "stdio"]
    else:
        cmd += ["--transport", "streamable-http", "--host", args.host, "--port", str(args.port)]

    os.execv(sys.executable, cmd)  # replace this process with the server


if __name__ == "__main__":
    main()
