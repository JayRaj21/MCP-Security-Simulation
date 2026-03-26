"""
Simulated MCP Server — the legitimate server that clients want to talk to.

Exposes a simplified MCP-style HTTP API:
    GET  /mcp/tools/list  — returns the tool catalogue
    POST /mcp/tools/call  — executes a tool and returns the result
    GET  /mcp/health      — liveness check

Security mode (controlled by SECURITY_ENABLED):
    - Verifies HMAC-SHA256 signatures on incoming requests
    - Rejects requests with missing or invalid signatures (HTTP 401)
    - Signs all outgoing responses
"""
import ast
import logging
import uuid

from flask import Flask, jsonify, request

from security import attach_sig, verify_and_strip

# Set by demo.py before the server thread starts.
# Checked at request-time so toggling between demo runs works correctly.
SECURITY_ENABLED = False

app = Flask(__name__)
logging.getLogger("werkzeug").setLevel(logging.ERROR)

# ─── Tool catalogue ──────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "calculator",
        "description": "Perform arithmetic calculations",
        "params": ["expression"],
    },
    {
        "name": "weather",
        "description": "Get current weather for a city",
        "params": ["city"],
    },
    {
        "name": "bank_transfer",
        "description": "Transfer funds between accounts",
        "params": ["amount", "from_account", "to_account"],
    },
    {
        "name": "user_lookup",
        "description": "Look up a user profile by ID",
        "params": ["user_id"],
    },
]

# Simulated user database with sensitive data
USERS = {
    "user-42": {"name": "Alice Smith",  "email": "alice@example.com",  "balance": 12450.00},
    "user-17": {"name": "Bob Jones",    "email": "bob@example.com",    "balance": 3200.50},
    "user-99": {"name": "Carol Davis",  "email": "carol@example.com",  "balance": 89000.00},
}


# ─── Helpers ─────────────────────────────────────────────────────────────────

def slog(msg: str) -> None:
    print(f"\033[34m[SERVER]\033[0m {msg}")


def safe_eval(expr: str) -> float:
    """Evaluate an arithmetic expression safely using Python's AST."""
    tree = ast.parse(expr, mode="eval")
    allowed = (
        ast.Expression, ast.BinOp, ast.UnaryOp, ast.Constant,
        ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Pow, ast.Mod,
        ast.USub, ast.UAdd,
    )
    for node in ast.walk(tree):
        if not isinstance(node, allowed):
            raise ValueError(f"Disallowed expression node: {type(node).__name__}")
    return eval(compile(tree, "<string>", "eval"))  # noqa: S307 — guarded by AST check


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/mcp/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/mcp/tools/list", methods=["GET"])
def list_tools():
    payload = {"tools": TOOLS}
    if SECURITY_ENABLED:
        slog("Signing tools/list response")
        return jsonify(attach_sig(payload))
    return jsonify(payload)


@app.route("/mcp/tools/call", methods=["POST"])
def call_tool():
    data = request.get_json(force=True)

    if SECURITY_ENABLED:
        data, valid = verify_and_strip(data)
        if not valid:
            slog("REJECTED: invalid or missing request signature")
            return jsonify({"error": "invalid signature", "code": 401}), 401
        slog("Request signature verified OK")

    tool = data.get("tool", "")
    params = data.get("params", {})
    slog(f"Executing '{tool}' with params: {params}")

    result = _dispatch(tool, params)

    if SECURITY_ENABLED:
        return jsonify(attach_sig(result))
    return jsonify(result)


def _dispatch(tool: str, params: dict) -> dict:
    if tool == "calculator":
        try:
            value = safe_eval(params.get("expression", "0"))
            slog(f"calculator result: {value}")
            return {"tool": tool, "result": value}
        except Exception as exc:
            return {"tool": tool, "error": str(exc)}

    if tool == "weather":
        city = params.get("city", "Unknown")
        return {
            "tool": tool,
            "result": {
                "city": city,
                "temperature": "72°F",
                "conditions": "Partly Cloudy",
                "humidity": "45%",
            },
        }

    if tool == "bank_transfer":
        amount   = params.get("amount", 0)
        from_acc = params.get("from_account", "")
        to_acc   = params.get("to_account", "")
        txn_id   = f"TXN-{uuid.uuid4().hex[:8].upper()}"
        slog(f"Transfer confirmed: ${amount} from {from_acc} to {to_acc} [{txn_id}]")
        return {
            "tool": tool,
            "result": {
                "status": "confirmed",
                "amount": amount,
                "from_account": from_acc,
                "to_account": to_acc,
                "transaction_id": txn_id,
            },
        }

    if tool == "user_lookup":
        user_id = params.get("user_id", "")
        user = USERS.get(user_id)
        if user:
            return {"tool": tool, "result": user}
        return {"tool": tool, "error": f"User '{user_id}' not found"}

    return {"tool": tool, "error": f"Unknown tool: '{tool}'"}
