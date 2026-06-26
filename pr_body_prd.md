# Add Product Requirements Document (PRD v1.0)

## Summary

Adds the canonical Product Requirements Document (PRD) for Agent-Alpha. This document defines WHY/WHO/WHAT-is-sellable, while ADR.md owns HOW (architecture, components, protocols).

## Changes

### Added Files

- **docs/PRD.md**
  - Problem statement: Authorized red-team capacity in Indonesia/SE Asia is scarce, slow, and expensive
  - Target user: CISO/Head of Security at Indonesian & SE Asian enterprise and mid-market
  - Jobs-to-be-done: Prove exploitability, show attack path, payable report, re-test
  - MVP: WebApp engagement (Alpha→Omega end-to-end)
  - KPIs: FP rate <20%, ≥1 payable finding, 100% proof artifacts, report styles, bounded time
  - Differentiator: Proves exploitability, attack-graph narrative, cross-engagement intelligence, local templates
  - Success Condition: Find something scanner missed, prove exploitable, produce payable report
  - Out of scope: Non-security capabilities, unauthorized testing, self-modifying code, generic scanning
  - Pricing: Below manual red team, above scanner license
  - Open product decisions: Engagement profile priority, approval channel, VERIFY mode

## Design Decisions

### Canonical Boundary
- PRD owns WHY/WHO/WHAT-is-sellable
- ADR.md owns HOW (architecture, components, protocols)
- On any conflict, ADR wins
- No architecture restatement in PRD

### KPI-Driven Development
- False-positive rate <20% (live-fire scoring)
- ≥1 payable finding per engagement
- 100% proof artifacts for critical findings
- Executive + Technical + Remediation report styles
- Bounded time-to-report

### Success Condition (North Star)
> Agent-Alpha finds something a conventional scanner missed, proves it is exploitable, and produces a report a client would pay for.

Everything in scope serves this single bar.

## Testing

No code changes, only documentation. No tests required.

## Checklist

- [x] PRD.md created
- [x] Canonical boundary defined
- [x] Target user defined
- [x] Jobs-to-be-done defined
- [x] MVP defined
- [x] KPIs defined
- [x] Differentiator defined
- [x] Success condition defined
- [x] Out of scope defined
- [x] Pricing direction defined
- [x] Open product decisions tracked

## Next Steps

- Review PRD against current implementation
- Update PRD as Phase 3 progresses
- Track open product decisions in ADR
