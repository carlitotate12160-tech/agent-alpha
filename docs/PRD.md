# Agent-Alpha — Product Requirements Document (PRD)

**Version:** 1.0
**Status:** Active — Phase 2 code sealed, Phase 3 in progress
**Owner:** Natanael (Eko)
**Last updated:** 2026-06-26

---

> **Legal & Authorization Notice.** Agent-Alpha is an authorized commercial red-team
> platform. Every engagement requires a signed SOW + written authorization, verified
> by a non-bypassable authorization gate (Conductor) before any offensive action.
> Testing is performed ONLY against client-owned systems with explicit consent.

---

## 0. Canonical Boundary (read first)

This PRD owns **WHY / WHO / WHAT-is-sellable**.
`docs/ADR.md` owns **HOW** (architecture, components, protocols).

**On any architecture conflict, ADR wins.** This document must never restate or
re-decide architecture — it links to it. If a statement here can be derived from
ADR or a phase test contract, it does not belong here.

Related canonical docs (do not duplicate their content):
`ADR.md` (architecture) · `PHASE_*_TEST_CONTRACT.md` (definition of done) ·
`PROGRESS_TRACKER.md` (status) · `OPERATIONAL_REFERENCE.md` (runbook).

---

## 1. Problem (Why this exists)

Authorized red-team capacity in Indonesia / SE Asia is scarce, slow, and expensive.
Conventional scanners (Nessus, Acunetix, nuclei) report *vulnerability existence* but
not *exploitability* — leaving clients a backlog of unprioritized "criticals" with no
proof, and leaving SME/enterprise buyers unable to afford a full manual red team.

**The gap Agent-Alpha fills:** an autonomous engagement that proves a finding is
*actually exploitable*, composes the attack into a narrative path, and outputs a
report a client will pay for — at a price point a scanner-plus-consultant cannot match.

## 2. Target user & buyer

- **Buyer:** CISO / Head of Security / IT Manager at Indonesian & SE Asian enterprise
  and mid-market (SME) — banking, government-adjacent, healthcare, ERP-heavy orgs.
- **User of the report:** internal security/blue team + management/compliance.
- **Geography first:** Indonesia, then SE Asia. Local-context templates are a moat.

## 3. Jobs-to-be-done

1. "Prove to me which of my findings an attacker can *actually* exploit." (triage by proof)
2. "Show me the *path* from internet to crown-jewel data, not a flat CVE list." (narrative)
3. "Give me a report I can hand to management and an auditor." (executive + technical + remediation)
4. "Do it again next quarter and tell me what changed." (cross-engagement intelligence / re-test)

## 4. Minimum Sellable Unit (MVP)

**One authorized WebApp engagement** that runs the kill chain through reporting and
produces a payable report. Sellable scope ladder (priority order):

1. **WebApp engagement** (current focus) — Alpha→Omega end-to-end.
2. Cloud / AD / Phishing-impact engagement profiles — *later, post-WebApp* (priority TBD, see ADR open decisions).

An engagement is "sellable" only when it meets the Success Condition (§7).

## 5. Success metrics / KPIs

| KPI | Target | Source of truth |
|-----|--------|-----------------|
| False-positive rate in findings | **< 20%** | live-fire scoring (`live_fire/`) |
| Payable findings per engagement | **≥ 1** proven-exploitable finding | engagement scorecard |
| Proof artifact attached to each "critical" | **100%** | AttackGraph proof_artifacts |
| Report styles delivered | Executive + Technical + Remediation | Omega output |
| Time-to-report per WebApp engagement | bounded by engagement time_budget | Bounded Autonomy stop conditions |

A "finding" with no proof artifact does **not** count toward any KPI (no silent success).

## 6. Differentiator (the moat)

1. **Proves exploitability**, not just existence — the core promise.
2. **Attack-graph narrative** — internet→crown-jewel path, not a flat CVE dump.
3. **Cross-engagement intelligence** — learns reliable plays across engagements (data/playbook only).
4. **Indonesia/SEA-specific templates** — local stacks & system categories conventional tools ignore.

## 7. Success Condition (North Star)

> Agent-Alpha finds something a conventional scanner missed, proves it is exploitable,
> and produces a report a client would pay for.

Everything in scope serves this single bar. A feature that does not move a KPI in §5
or this condition is out of scope by default.

## 8. Out of scope (product-level)

- Non-security capabilities of any kind (coding / devops / research personas).
- Unauthorized testing, or any action without a signed SOW + Conductor authorization.
- Self-modifying agent code (learning is data/playbook only — see ADR).
- Generic vulnerability scanning sold as the product (scanning is an input, not the offer).
- Architecture decisions — those live in ADR, not here.

## 9. Pricing / packaging (direction, not commitment)

Per-engagement pricing positioned **below a full manual red team, above a scanner
license** — value anchored on *proven-exploitable findings + auditable report*, not
on number of hosts scanned. Re-test / continuous-engagement as a recurring upsell.

## 10. Open product decisions (track, do not bury in ADR)

- Engagement profile priority after WebApp: Cloud / AD / Phishing-impact?
- Approval channel for SOW/authorization: Telegram only vs web dashboard?
- VERIFY / re-test mode as a sellable recurring SKU: Phase 2 surface or Phase 6?

*(Architecture form of these decisions is tracked in ADR; this section tracks only the
product/commercial framing.)*
