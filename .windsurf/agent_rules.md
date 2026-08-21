# Agent-Alpha — Agent Rules (RELOCATED POINTER)

> This path is not auto-loaded and its prior content had drifted (stale phase gates, an
> outdated model matrix, an A2A JSON schema that did not match `proto/a2a.proto`, and
> per-agent handoff dataclasses that do not exist in the codebase). Retired to a pointer.

Canonical authority:
- **Role + doctrine:** `CLAUDE.md` and `.devin/skills/agent-alpha-architect/SKILL.md`.
- **Architecture decisions:** `docs/ADR.md`.
- **Current status / NEXT slice:** `docs/Session_Handoff.md`.
- **Gap ledger:** `docs/BUGS_AND_GAPS.md`.
- **A2A schema (single source):** `proto/a2a.proto`.
- **Doc-status rule:** run `python scripts/check_doc_status.py`; that script defines the allowed
  status vocabulary.

Do not re-add hardcoded handoff types or schemas here; they belong in `proto/a2a.proto` and code.
