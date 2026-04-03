PYTHON  := python3
VENV    := .venv
PIP     := $(VENV)/bin/pip
PYBIN   := $(VENV)/bin/python3

# ── setup ────────────────────────────────────────────────────────────────────
$(VENV):
	$(PYTHON) -m venv $(VENV)
	$(PIP) install -q -r requirements.txt

# ── targets ───────────────────────────────────────────────────────────────────
.PHONY: webapp server shell demo help

webapp: $(VENV)           ## Start the web UI  (http://127.0.0.1:8080)  ← START HERE
	$(PYBIN) webapp.py

server: $(VENV)           ## Start the FastMCP server  (http://127.0.0.1:8000/mcp)
	$(PYBIN) server.py

shell: $(VENV)            ## Open the interactive security shell
	$(PYBIN) shell.py

demo: $(VENV)             ## Run the automated demo walkthrough (server must be running)
	$(PYBIN) demo_client.py

# ── default ───────────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  make webapp    — start the web UI  (http://127.0.0.1:8080)  ← START HERE"
	@echo "  make server    — start the FastMCP/MCP server"
	@echo "  make shell     — open the interactive CLI shell"
	@echo "  make demo      — run the automated demo (server must be running)"
	@echo ""

.DEFAULT_GOAL := help
