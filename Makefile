PYTHON  := python3
VENV    := .venv
PIP     := $(VENV)/bin/pip
PYBIN   := $(VENV)/bin/python3

# ── setup — re-runs pip install whenever requirements.txt changes ─────────────
$(VENV)/.installed: requirements.txt
	$(PYTHON) -m venv $(VENV)
	$(PIP) install -q -r requirements.txt
	touch $@

# ── targets ───────────────────────────────────────────────────────────────────
.PHONY: web server shell demo help

web: $(VENV)/.installed           ## Start the web UI  (http://127.0.0.1:8080)  ← START HERE
	$(PYBIN) webapp.py

server: $(VENV)/.installed        ## Start the FastMCP server  (http://127.0.0.1:8000/mcp)
	$(PYBIN) server.py

shell: $(VENV)/.installed         ## Open the interactive security shell
	$(PYBIN) shell.py

demo: $(VENV)/.installed          ## Run the automated demo walkthrough (server must be running)
	$(PYBIN) demo_client.py

# ── default ───────────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  make web       — start the web UI  (http://127.0.0.1:8080)  ← START HERE"
	@echo "  make server    — start the FastMCP/MCP server"
	@echo "  make shell     — open the interactive CLI shell"
	@echo "  make demo      — run the automated demo (server must be running)"
	@echo ""

.DEFAULT_GOAL := help
