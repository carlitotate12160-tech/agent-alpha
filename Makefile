# Agent-Alpha — Quality Gates
# Run: make check  (ruff + mypy)
# Run: make test   (all tests)
# Run: make all    (check + test)

VENV := .venv/bin
PYTHON := $(VENV)/python3
RUFF := $(VENV)/ruff
MYPY := $(VENV)/mypy
PYTEST := $(VENV)/pytest

.PHONY: all check lint lint-fix typecheck quality test test-protected test-phase0 proto

all: check test

# ── Codegen ────────────────────────────────────

# Generate Python + Go stubs from the canonical A2A contract.
# Python stubs are emitted into the agent_alpha/a2a package so they import as
# `from agent_alpha.a2a import a2a_pb2`.
# --pyi_out is REQUIRED, not cosmetic: without the .pyi stub, mypy cannot see
# static attributes on generated enums (EngagementState.CREATED, etc.) because
# protoc's runtime .py builds them via _descriptor_pool.AddSerializedFile()
# (opaque binary descriptor, not a plain class). Omitting --pyi_out is what
# previously forced disable_error_code=["attr-defined"] overrides in
# pyproject.toml for authorization.py/emergency.py/main.py — those overrides
# are now removed; this flag is the actual fix, not the override.
proto:
	$(PYTHON) -m grpc_tools.protoc -I proto --python_out=agent_alpha/a2a --grpc_python_out=agent_alpha/a2a --pyi_out=agent_alpha/a2a proto/a2a.proto
	-protoc -I proto --go_out=. --go-grpc_out=. proto/a2a.proto || echo "Go codegen skipped (protoc not available)"

# ── Quality gates ──────────────────────────────

check: lint typecheck

lint:
	$(RUFF) check agent_alpha/
	$(RUFF) format --check agent_alpha/

lint-fix:
	$(RUFF) check --fix agent_alpha/
	$(RUFF) format agent_alpha/

typecheck:
	$(MYPY) agent_alpha/ --ignore-missing-imports

quality:
	make lint
	make typecheck
	$(PYTEST) tests/PROTECTED/ tests/phase_0/ -v

# ── Tests ──────────────────────────────────────

test: test-protected test-phase0

test-protected:
	@echo "━━━ PROTECTED CONTRACT TESTS (DO NOT MODIFY) ━━━"
	$(PYTEST) tests/PROTECTED/ -v --tb=short

test-phase0:
	@echo "━━━ PHASE 0 TESTS ━━━"
	$(PYTEST) tests/phase_0/ -v --tb=short
