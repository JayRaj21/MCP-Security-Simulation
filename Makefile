PYTHON  := python3
VENV    := .venv
PIP     := $(VENV)/bin/pip
PYBIN   := $(VENV)/bin/python3

# ── setup ────────────────────────────────────────────────────────────────────
$(VENV):
	$(PYTHON) -m venv $(VENV)
	$(PIP) install -q -r v2/requirements.txt

# ── v2 targets ───────────────────────────────────────────────────────────────
.PHONY: server shell demo help

server: $(VENV)           ## Start the FastMCP server  (http://127.0.0.1:8000/mcp)
	$(PYBIN) v2/server.py

shell: $(VENV)            ## Open the interactive security shell  ← START HERE
	$(PYBIN) v2/shell.py

demo: $(VENV)             ## Run the automated demo walkthrough (server must be running)
	$(PYBIN) v2/demo_client.py

# ── default ───────────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  Terminal 1:  make server   — start the FastMCP server"
	@echo "  Terminal 2:  make shell    — open the interactive shell  ← START HERE"
	@echo "               make demo     — run the automated demo instead"
	@echo ""

.DEFAULT_GOAL := help
