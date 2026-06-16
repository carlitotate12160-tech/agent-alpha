# Agent-Alpha — Quality Gates
# Run: make check  (ruff + mypy)
# Run: make test   (all tests)
# Run: make all    (check + test)

VENV := .venv/bin
PYTHON := $(VENV)/python3
RUFF := $(VENV)/ruff
MYPY := $(VENV)/mypy
PYTEST := $(VENV)/pytest

.PHONY: all check lint typecheck test test-protected test-phase0 proto

all: check test

# ── Codegen ────────────────────────────────────

# Generate Python + Go stubs from the canonical A2A contract.
proto:
	python -m grpc_tools.protoc -I proto --python_out=. --grpc_python_out=. proto/a2a.proto
	protoc -I proto --go_out=. --go-grpc_out=. proto/a2a.proto

# ── Quality gates ──────────────────────────────

check: lint typecheck

lint:
	$(RUFF) check . --config pyproject.toml
	$(RUFF) format --check . --config pyproject.toml

typecheck:
	$(MYPY) conductor/ --config-file pyproject.toml || true

# ── Tests ──────────────────────────────────────

test: test-protected test-phase0

test-protected:
	@echo "━━━ PROTECTED CONTRACT TESTS (DO NOT MODIFY) ━━━"
	$(PYTEST) tests/PROTECTED/ -v --tb=short

test-phase0:
	@echo "━━━ PHASE 0 TESTS ━━━"
	$(PYTEST) tests/phase_0/ -v --tb=short
