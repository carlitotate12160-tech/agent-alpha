"""Contract: PlaybookEngine — the RULE tier of Opsi B.

The whole point of Opsi B: for situations with precedent, the decision is
deterministic and the LLM is NEVER consulted. The LLM tier exists only for
novel observations the playbook has no answer for.

This file proves three things:
  1. A known observation (Laravel debug page) yields a deterministic decision.
  2. The same input ALWAYS yields the same output (testable adaptivity).
  3. A novel observation yields None — the explicit signal to escalate to
     SINGLE_LLM. The engine itself contains no LLM and cannot call one
     (separation of tiers).
"""

from __future__ import annotations

import pathlib

import pytest

from agent_alpha.config import constants
from agent_alpha.tools.playbook import PlaybookEngine

PLAYBOOK_DIR = pathlib.Path(__file__).parent / "fixtures" / "playbooks"


@pytest.fixture
def engine() -> PlaybookEngine:
    return PlaybookEngine.from_directory(PLAYBOOK_DIR)


def _laravel_observation() -> dict[str, object]:
    return {
        "body": (
            "<title>Whoops! There was an error.</title>"
            "Illuminate\\Database\\QueryException ... Laravel v10.3.1"
        ),
        "headers": {"x-powered-by": "PHP/8.2.4"},
    }


def test_known_observation_matches_deterministically(engine: PlaybookEngine) -> None:
    decision = engine.match(_laravel_observation())
    assert decision is not None
    assert decision.tool == "laravel_debug_probe"
    assert decision.tier == constants.LLM_TIER_RULE
    assert decision.technique_id == "T1592.002"


def test_same_input_always_same_output(engine: PlaybookEngine) -> None:
    """Adaptive but consistent: 100 identical inputs -> 100 identical tools.
    This is how Opsi B answers 'how do you prove Alpha is adaptive yet
    reproducible?' — the RULE tier is a pure function."""
    obs = _laravel_observation()
    tools = {(engine.match(obs).tool) for _ in range(100)}
    assert tools == {"laravel_debug_probe"}


def test_novel_observation_returns_none_to_signal_escalation(engine: PlaybookEngine) -> None:
    """No precedent -> None. None is the ONLY way the engine asks the
    orchestrator to fall through to SINGLE_LLM. It must never guess."""
    novel = {"body": "<title>Acme Bespoke Appliance Admin</title>", "headers": {}}
    assert engine.match(novel) is None


def test_engine_has_no_llm_dependency(engine: PlaybookEngine) -> None:
    """Tier separation: the RULE tier cannot reach an LLM. If a future edit
    wires an LLM into the playbook engine, this fails — the escalation
    decision belongs to the orchestrator, not the playbook."""
    assert not hasattr(engine, "llm")
    assert not hasattr(engine, "provider")


# ---------------------------------------------------------------------------
# Bug #2/#6 — exclude_tools: an already-run tool's rule must not keep
# pre-empting the LLM tier for every subsequent matching page.
# ---------------------------------------------------------------------------


def test_exclude_tools_skips_matching_rule_and_signals_escalation(
    engine: PlaybookEngine,
) -> None:
    """Same observation that deterministically matches laravel_debug_probe
    (test_known_observation_matches_deterministically) returns None — the
    escalation signal — once that tool is in exclude_tools, exactly as if
    the page were genuinely novel."""
    decision = engine.match(
        _laravel_observation(), exclude_tools=frozenset({"laravel_debug_probe"})
    )
    assert decision is None


def test_exclude_tools_default_is_empty_zero_behaviour_change(engine: PlaybookEngine) -> None:
    """Every pre-existing caller of match(observation) — no exclude_tools arg
    — must see byte-identical behaviour to before this fix."""
    decision = engine.match(_laravel_observation())
    assert decision is not None
    assert decision.tool == "laravel_debug_probe"


def test_exclude_tools_only_affects_the_named_tool(engine: PlaybookEngine) -> None:
    """Excluding an unrelated tool name must not suppress a real match —
    exclusion is scoped to the specific tool, not 'any rule fired before'."""
    decision = engine.match(_laravel_observation(), exclude_tools=frozenset({"some_other_tool"}))
    assert decision is not None
    assert decision.tool == "laravel_debug_probe"


# ---------------------------------------------------------------------------
# Bug #14 — from_directory(phase=...): Alpha (RECON_ONLY) must be structurally
# unable to load an access-phase rule, not merely rely on it not matching.
# ---------------------------------------------------------------------------


def _write_playbook(directory: pathlib.Path, filename: str, *, phase: str, tool: str) -> None:
    directory.joinpath(filename).write_text(
        f"""\
name: {tool}_rule
version: 1
phase: {phase}
match:
  any_indicator:
    - body_contains: "{tool}-marker"
action:
  tool: {tool}
  tier: rule
  technique_id: "T0000"
  rationale: "test fixture"
"""
    )


def test_phase_filter_excludes_other_phase_rules(tmp_path: pathlib.Path) -> None:
    _write_playbook(tmp_path, "recon_rule.yaml", phase="recon", tool="recon_tool")
    _write_playbook(tmp_path, "access_rule.yaml", phase="access", tool="access_tool")

    recon_engine = PlaybookEngine.from_directory(tmp_path, phase="recon")

    assert recon_engine.match({"body": "access_tool-marker", "headers": {}}) is None, (
        "an access-phase rule was loaded into a phase='recon' engine — Alpha "
        "(RECON_ONLY) must never even be ABLE to match an access-phase rule"
    )
    decision = recon_engine.match({"body": "recon_tool-marker", "headers": {}})
    assert decision is not None
    assert decision.tool == "recon_tool"


def test_phase_filter_none_preserves_load_everything(tmp_path: pathlib.Path) -> None:
    """The default (phase=None) is the pre-fix behaviour, unchanged — every
    existing caller that doesn't pass phase= must see zero difference."""
    _write_playbook(tmp_path, "recon_rule.yaml", phase="recon", tool="recon_tool")
    _write_playbook(tmp_path, "access_rule.yaml", phase="access", tool="access_tool")

    engine = PlaybookEngine.from_directory(tmp_path)

    assert engine.match({"body": "access_tool-marker", "headers": {}}) is not None
    assert engine.match({"body": "recon_tool-marker", "headers": {}}) is not None
