"""
MCP Client library.

Connects to an MCP server (or MITM proxy) and makes tool calls.
When security is enabled, it:
    - Signs outgoing requests with HMAC-SHA256
    - Verifies signatures on all incoming responses
    - Raises SecurityError if any response fails verification
"""
import requests

from security import attach_sig, verify_and_strip

# Toggled by demo.py before demo scenarios run.
SECURITY_ENABLED = False


class SecurityError(Exception):
    """Raised when a response fails HMAC-SHA256 signature verification."""


class MCPClient:
    """Simple HTTP client for the simulated MCP server."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self._session = requests.Session()

    def _clog(self, msg: str) -> None:
        print(f"\033[96m[CLIENT]\033[0m {msg}")

    def list_tools(self) -> list:
        """
        Request the list of available tools from the server.

        Raises:
            SecurityError: If security is enabled and the response signature
                           is missing or does not match the payload.
        """
        resp = self._session.get(f"{self.base_url}/mcp/tools/list", timeout=5)
        data = resp.json()

        if SECURITY_ENABLED:
            self._clog("Verifying tools/list response signature…")
            data, valid = verify_and_strip(data)
            if not valid:
                raise SecurityError(
                    "Tool list signature verification FAILED — "
                    "response was tampered with or was never signed"
                )
            self._clog("Signature OK \u2713")

        return data.get("tools", [])

    def call_tool(self, tool: str, params: dict) -> dict:
        """
        Call a tool on the server and return the result.

        When security is enabled the request payload is signed before
        sending, and the response signature is verified before returning.

        Raises:
            SecurityError: If the response signature is invalid.
        """
        payload = {"tool": tool, "params": params}

        if SECURITY_ENABLED:
            payload = attach_sig(payload)
            self._clog(f"Sending signed request for tool '{tool}'")
        else:
            self._clog(f"Sending request for tool '{tool}'")

        resp = self._session.post(
            f"{self.base_url}/mcp/tools/call",
            json=payload,
            timeout=5,
        )

        # Server rejected a tampered request
        if resp.status_code == 401:
            self._clog("Server returned 401 — tampered request was rejected by server")
            return {"error": "server rejected request (401)", "code": 401}

        data = resp.json()

        if SECURITY_ENABLED:
            self._clog(f"Verifying response signature for tool '{tool}'…")
            data, valid = verify_and_strip(data)
            if not valid:
                raise SecurityError(
                    f"Response signature verification FAILED for tool '{tool}' — "
                    "response was tampered with or was never signed"
                )
            self._clog("Signature OK \u2713")

        return data
