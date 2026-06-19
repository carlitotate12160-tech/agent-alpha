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
