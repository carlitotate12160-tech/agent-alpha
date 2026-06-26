# agent_alpha/tools/templates/cms/laravel_finding.py
"""Laravel debug/config-exposure finding template (ADR §12.16).

SEAM ONLY. Claude authors this non-offensive skeleton: ids, MITRE mapping, auth tier,
and method signatures that conform to `tools.contracts.Template`. The build()/verify()
BODIES are DeepSeek's lane (offensive) — see deepseek_prompt_laravel_finding.md, §3/§4.

Until DeepSeek implements them, both raise NotImplementedError so the RED contract
(tests/phase_2/test_laravel_finding.py) FAILS by construction — no dead code counted
as done (anti-Lyndon #2), no silent success (anti-Lyndon #3).

Scope: RECON_ONLY. This template only *detects + proves* an APP_DEBUG=true / config
exposure (read-only). Acting on any leaked secret is a later phase + higher auth tier.
"""

from __future__ import annotations

import re
from typing import Any

from agent_alpha.llm.redaction import redact_secrets
from agent_alpha.tools.contracts import TargetContext, ToolResult


class LaravelFindingTemplate:
    """Detects and PROVES a Laravel debug/config exposure (APP_DEBUG=true env leak).

    Structurally conforms to `agent_alpha.tools.contracts.Template`.
    """

    template_id: str = "laravel_debug_exposure"
    mitre_technique: str = "T1592.002"  # Gather Victim Host Info — Software
    required_auth: str = "RECON_ONLY"

    def build(self, ctx: TargetContext) -> dict[str, Any]:
        """OFFENSIVE BODY -> DeepSeek (prompt §3).

        Construct the read-only probe request for `ctx.target`. MUST act only on the
        already-screened `ctx.target` (never invent a host — CWE-918), and stay within
        RECON_ONLY (no exploitation, GET/HEAD-style probe under the engagement budget).
        """
        # RECON_ONLY: GET request to the target only
        return {
            "method": "GET",
            "url": ctx.target,
            "headers": {
                "User-Agent": "Mozilla/5.0 (compatible; Agent-Alpha/1.0; +https://agent-alpha.example/bot)",
            },
        }

    def verify(self, response: dict[str, Any]) -> ToolResult:
        """OFFENSIVE BODY -> DeepSeek (prompt §4).

        Turn a response into a ToolResult — PROOF, not assumption. Return success ONLY
        when the response confirms a real exposure AND a proof artifact is captured.
        A version string or a mere 500 is a hypothesis, not a finding. Ambiguous or
        empty -> success=False with no findings/proof.
        """
        body = response.get("body", "")
        url = response.get("url", "")

        # Empty or invalid response -> failure (no crash)
        if not body or not body.strip():
            return ToolResult(
                tool=self.template_id,
                success=False,
                confidence=0.0,
                findings=(),
                proof_artifacts=(),
            )

        # Playbook signatures: debug-page text indicators + version regex.
        # A version string alone is NOT a finding (spec §4.1) — it only tells us
        # Laravel is running, not that APP_DEBUG=true is exposed. We require at
        # least one debug-page text signature ("Whoops" or "Illuminate") as proof
        # of an actual debug page. The version match is corroborating evidence.
        debug_signatures = ("Whoops", "Illuminate")
        version_pattern = re.compile(r"Laravel v[0-9]+")

        matched_sig = next((sig for sig in debug_signatures if sig in body), None)
        if matched_sig is None:
            return ToolResult(
                tool=self.template_id,
                success=False,
                confidence=0.0,
                findings=(),
                proof_artifacts=(),
            )

        has_version = version_pattern.search(body) is not None

        # Redact secrets before they enter findings or proof (spec §4.4).
        redacted_body = redact_secrets(body)

        # Extract a focused snippet around the first signature match for evidence.
        sig_pos = redacted_body.find(matched_sig)
        snippet_start = max(0, sig_pos - 100)
        snippet_end = min(len(redacted_body), sig_pos + 400)
        redacted_snippet = redacted_body[snippet_start:snippet_end]

        evidence_parts = [f"Laravel debug page signature '{matched_sig}' found"]
        if has_version:
            evidence_parts.append("version string corroborates Laravel framework")
        evidence_parts.append("APP_DEBUG=true exposure confirmed")

        finding = {
            "type": "laravel_debug_exposure",
            "evidence": "; ".join(evidence_parts),
            "redacted_snippet": redacted_snippet,
        }

        # Proof artifact: REDACTED evidence captured from the response.
        proof_ref = f"proof:laravel_debug_exposure:{url}"

        return ToolResult(
            tool=self.template_id,
            success=True,
            confidence=0.85 if has_version else 0.75,
            findings=(finding,),
            proof_artifacts=(proof_ref,),
        )
