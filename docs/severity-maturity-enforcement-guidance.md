# Severity + Maturity Enforcement Guidance

This guide provides a **production-first default** for rolling out packs with low false-positive risk.

Use it to choose:
- Initial enforcement mode: `log`, `challenge`, `rate-limit`, or `block`
- Minimum observation window before promotion
- Promotion path to stronger enforcement

> If your environment is high-risk (active exploitation, sensitive admin/API paths), you may accelerate promotion with explicit approval.

## Quick Decision Table

| Severity | Maturity | Recommended Initial Action | Minimum Review Window | Default Promotion Path |
|---|---|---|---|---|
| **Critical** | **Stable** | **block** (or `challenge` if user-facing flow risk) | 24-48h | block -> tune exceptions only |
| **Critical** | **Beta** | challenge | 48-72h | challenge -> block |
| **Critical** | **Experimental** | log + targeted rate-limit | 3-7d | log/rate-limit -> challenge -> block |
| **High** | **Stable** | challenge | 48-72h | challenge -> block |
| **High** | **Beta** | log + challenge on high-confidence paths | 3-5d | log/challenge -> challenge -> block |
| **High** | **Experimental** | log | 5-7d | log -> challenge/rate-limit -> block |
| **Medium** | **Stable** | log (or rate-limit for abuse patterns) | 5-7d | log -> challenge/rate-limit -> block (optional) |
| **Medium** | **Beta** | log | 7-10d | log -> challenge/rate-limit |
| **Medium** | **Experimental** | log | 10-14d | log -> scoped challenge/rate-limit |
| **Low** | **Stable** | log | 7-14d | keep log or scoped challenge/rate-limit |
| **Low** | **Beta** | log | 14d | keep log; promote only with strong signal |
| **Low** | **Experimental** | log | 14-21d | keep log; avoid broad enforcement |

## Operational Rules of Thumb

1. **Maturity gates aggressiveness**: lower maturity starts safer, even at high severity.
2. **Prefer scoped enforcement first**: admin/auth/API endpoints before global rollout.
3. **Rate-limit before block** for abuse-driven packs when actor identity is noisy.
4. **Require clean trend before promotion**: no sustained false-positive spikes for at least one full business cycle.
5. **Rollback criteria must be pre-defined**: e.g., auth failures, checkout drops, or support-ticket spikes.

## Promotion Checklist (Concise)

Promote one step (`log` -> `challenge` -> `rate-limit/block`) only when:
- Alert volume is stable and explained.
- False positives are reviewed and exception rules added.
- App owner signs off for impacted paths.
- Rollback command/change is ready.

## Suggested Review Cadence

- **Day 0**: Deploy initial mode from table.
- **Day 1-2**: Validate logs, tune obvious false positives.
- **End of window**: Decide promote/hold/rollback.
- **Post-promotion (24-48h)**: Confirm no business KPI regression.
