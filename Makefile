# AgentShield — local dev, no containers. Linux / WSL / macOS. (Windows: use ./dev.ps1)
PYTHON ?= python3.11
VENV   := backend/.venv
PY     := $(VENV)/bin/python
HOST   ?= 127.0.0.1
PORT   ?= 8000

.PHONY: setup dev backend frontend test test-backend test-frontend e2e build clean

$(PY):
	$(PYTHON) -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ required"'
	$(PYTHON) -m venv $(VENV)
	$(PY) -m pip install --upgrade pip

$(VENV)/.installed: backend/requirements.txt | $(PY)
	$(PY) -m pip install -r backend/requirements.txt
	touch $@

frontend/node_modules/.installed: frontend/package.json
	cd frontend && npm install --no-audit --no-fund
	touch $@

.env:
	cp .env.example .env
	@echo ">> Created .env from .env.example — fill in TARGET_HARNESS_ARN / TARGET_REGION / AWS_PROFILE."

setup: $(VENV)/.installed frontend/node_modules/.installed .env

# Runs the API (uvicorn --reload) and the Vite dev server together; Ctrl-C stops both.
dev: setup
	@trap 'kill 0' INT TERM EXIT; \
	$(PY) -m uvicorn agentshield.app:app --app-dir backend --host $(HOST) --port $(PORT) --reload --reload-dir backend/agentshield --timeout-graceful-shutdown 3 & \
	cd frontend && AGENTSHIELD_API=http://$(HOST):$(PORT) npm run dev

backend: setup
	$(PY) -m uvicorn agentshield.app:app --app-dir backend --host $(HOST) --port $(PORT) --reload --reload-dir backend/agentshield --timeout-graceful-shutdown 3

frontend: setup
	cd frontend && AGENTSHIELD_API=http://$(HOST):$(PORT) npm run dev

test: test-backend test-frontend

test-backend: $(VENV)/.installed
	cd backend && .venv/bin/python -m pytest -q

test-frontend: frontend/node_modules/.installed
	cd frontend && npx tsc -b && npm test

# Real server on a throwaway database, full workflow over HTTP (PyRIT + garak execution included).
e2e: $(VENV)/.installed
	cd backend && .venv/bin/python scripts/e2e_smoke.py

build: frontend/node_modules/.installed
	cd frontend && npm run build

clean:
	rm -rf $(VENV) frontend/node_modules frontend/dist
