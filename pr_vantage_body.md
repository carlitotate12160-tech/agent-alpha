Doc-only ADR update. No code change.

## §12.42 — Attacker Vantage + Footprint + Doctrine (expanded)
- Two axes pinned: **EXTERNAL** vantage + **AGENTLESS** footprint
- Attacker doctrine: exhaustive surface map, stop when exhausted (not when N paths fail), gated oracle-verified lanes one at a time, business-logic deferred to Phase 5/6
- Post-ex stays agentless via LOLBin (§8g) — "safe in production, nothing left behind"
- Internal/assumed-breach = later secondary profile via pivot

## §12.43 — Proof Standard (new)
- Payable finding needs BOTH: independent oracle (cross_verified) AND human-legible ProofArtifact (screenshot + HAR)
- Screenshot = EXHIBIT, not oracle (anti-#3 false success)
- Access/login oracle = auth-vs-unauth ground-truth diff (§12.32)
- Missing oracle or visual → downgrade, excluded from KPI

## Files changed
- `docs/ADR.md` — §12.42 replaced + §12.43 appended
- `docs/ADR_SUMMARY.md` — both §12 lines updated
- `docs/PRD.md` — §2 positioning updated

Both PROPOSED (lock on confirm).
