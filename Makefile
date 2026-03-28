PYTHON  := python3
VENV    := .venv
PIP     := $(VENV)/bin/pip
PYBIN   := $(VENV)/bin/python3

# ── setup ────────────────────────────────────────────────────────────────────
$(VENV):
	$(PYTHON) -m venv $(VENV)
	$(PIP) install -q -r v2/requirements.txt

# ── v2 targets ───────────────────────────────────────────────────────────────
.PHONY: server demo help

server: $(VENV)           ## Start the FastMCP server  (http://127.0.0.1:8000/mcp)
	$(PYBIN) v2/server.py

demo: $(VENV)             ## Run the interactive security demo (server must be running)
	$(PYBIN) v2/demo_client.py

# ── default ───────────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  make server   start the FastMCP server on http://127.0.0.1:8000/mcp"
	@echo "  make demo     run the interactive demo (open a second terminal)"
	@echo ""

.DEFAULT_GOAL := help
