# agent_alpha/tools/contracts.py
"""Canonical tool-layer contracts (ADR §12.16).

Claude authors these protocols + types (non-offensive glue). DeepSeek authors the
offensive BODIES — `Tool.run`, `Template.build`, `Template.verify` — in
tools/templates/* per-phase. One class per concept (#6). The registry + composer
(non-offensive glue, also Claude's) land once >= 2 real tools exist; a composer with
nothing to compose now would be dead code (#2).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from agent_alpha.config import constants


@dataclass(frozen=True)
class TargetContext:
    """Everything a tool needs to decide + act, projected from the AttackGraph (never
    raw caller input). The `target` is already in-scope + SSRF-screened (CWE-918)."""

    engagement_id: str
    tenant_id: str | None
    target: str
    tech_stack: dict[str, str] = field(default_factory=dict)
    open_ports: tuple[int, ...] = ()
    prior_findings: tuple[str, ...] = ()


@dataclass(frozen=True)
class ResourceBudget:
    """Bounded autonomy (§12.13 #2): every tool runs under a hard cap. `rate_limit_rps`
    is enforced by the egress RateLimiter we already built (single source, #7)."""

    max_requests: int
    max_seconds: float
    max_cost_usd: float
    rate_limit_rps: float = constants.DEFAULT_RATE_LIMIT_RPS


@dataclass(frozen=True)
class ToolResult:
    """Outcome of a tool/template. Success = VALIDATED non-empty output, enforced at
    construction (anti-Lyndon #3): you cannot build a 'successful' result with no
    finding — that is the silent-success bug, structurally forbidden here."""

    tool: str
    success: bool
    confidence: float
    findings: tuple[dict[str, Any], ...] = ()
    proof_artifacts: tuple[str, ...] = ()
    error: str | None = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0,1], got {self.confidence}")
        if self.success and not self.findings:
            raise ValueError(
                "a successful ToolResult must carry >= 1 finding (anti-Lyndon #3: "
                "no silent success — success requires validated, non-empty output)"
            )
        if not self.success and self.findings:
            raise ValueError("a failed ToolResult must not carry findings")


@runtime_checkable
class Template(Protocol):
    """An exploit/finding payload unit under tools/templates/<category>/. DeepSeek's
    lane entirely; Claude provides only this shape so the composer treats them uniformly."""

    template_id: str
    mitre_technique: str
    required_auth: str

    def build(self, ctx: TargetContext) -> dict[str, Any]:
        """OFFENSIVE BODY → DeepSeek. Construct the probe/payload for `ctx`. Must stay
        within `required_auth`."""
        ...

    def verify(self, response: dict[str, Any]) -> ToolResult:
        """OFFENSIVE BODY → DeepSeek. Turn a response into a ToolResult: PROOF, not
        assumption. 'version matches CVE' / 'csrf-token present' is a hypothesis, not a
        finding — return success only when exploitability is confirmed + a proof artifact
        captured. Ambiguous/empty → success=False."""
        ...


@runtime_checkable
class Tool(Protocol):
    """A capability the Conductor/agent may run. OFFENSIVE bodies are DeepSeek's; Claude
    owns the contract + the registry/composer that select and order tools."""

    name: str
    phase: str  # recon | access | exploit | post | lateral
    required_auth: str

    def applies_to(self, ctx: TargetContext) -> float:
        """Relevance 0..1 from tech_stack/context — NOT a hardcoded if-ladder (K11).
        Lets the registry/composer rank, not the agent guess."""
        ...

    def run(self, ctx: TargetContext, budget: ResourceBudget) -> ToolResult:
        """OFFENSIVE BODY → DeepSeek. Stay within budget; emit proof; never exceed
        required_auth; success only on validated output."""
        ...
