"""
Security layer for MCP Security Simulation.

Provides HMAC-SHA256 message signing and verification to protect
MCP messages from tampering by a man-in-the-middle attacker.

The shared secret would be exchanged out-of-band in a real system
(e.g., during a TLS-authenticated handshake or provisioning step).
"""
import hmac
import hashlib
import json

# Shared secret known only to the legitimate client and server.
# The MITM does NOT have this — which is why it cannot forge signatures.
SHARED_SECRET = b"mcp-demo-secret-key-2024-do-not-use-in-production"


def _canonical(payload: dict) -> bytes:
    """
    Serialize a payload to a canonical byte string for signing.
    Excludes the '_sig' field itself (to avoid circular dependency).
    Keys are sorted for deterministic output regardless of insertion order.
    """
    clean = {k: v for k, v in payload.items() if k != "_sig"}
    return json.dumps(clean, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(payload: dict) -> str:
    """Generate an HMAC-SHA256 hex digest for a payload dict."""
    return hmac.new(SHARED_SECRET, _canonical(payload), hashlib.sha256).hexdigest()


def verify(payload: dict, signature: str) -> bool:
    """
    Verify an HMAC-SHA256 signature against a payload.
    Uses constant-time comparison to prevent timing attacks.
    """
    expected = sign(payload)
    return hmac.compare_digest(expected, signature)


def attach_sig(payload: dict) -> dict:
    """Return a copy of the payload dict with a '_sig' field attached."""
    result = dict(payload)
    result["_sig"] = sign(payload)
    return result


def verify_and_strip(data: dict) -> tuple:
    """
    Extract and verify the '_sig' field from a received message.

    Returns:
        (clean_payload, True)  — if signature is present and valid
        (clean_payload, False) — if signature is missing or invalid
    """
    data = dict(data)
    sig = data.pop("_sig", None)
    if sig is None:
        return data, False
    return data, verify(data, sig)
