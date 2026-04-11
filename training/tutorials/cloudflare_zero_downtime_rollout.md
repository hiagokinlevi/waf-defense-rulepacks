# Tutorial: Zero-Downtime Cloudflare WAF Rollout

This tutorial focuses on how to expand Cloudflare protection without surprising application teams or breaking integrations.

## Strategy

Use four lanes of control:

1. visibility-only WAF rules
2. path-specific rate limits
3. browser-only bot challenges
4. hard blocks for operational surfaces

## Suggested Sequence

### Day 1

- Deploy GraphQL introspection and API abuse rules in log mode
- Deploy webhook burst protection in log mode

### Day 2

- Review Security Events by path, ASN, and country
- Document legitimate clients and candidate exclusions

### Day 3

- Deploy login challenge and password reset throttling
- Keep machine-to-machine auth outside browser challenge rules

### Day 4+

- Promote the cleanest controls first:
  - admin surface restrictions
  - debug and actuator restrictions
  - login challenge
  - API abuse rules

## What Preserves Uptime

- one rule family per promotion step
- explicit exclusions instead of expression weakening
- no browser challenge on machine clients
- separate handling for webhooks and callbacks

## Recommended Reading

- [`docs/deployment-guides/cloudflare.md`](../../docs/deployment-guides/cloudflare.md)
- [`docs/deployment-guides/cloudflare_api_security.md`](../../docs/deployment-guides/cloudflare_api_security.md)
- [`docs/review-checklists/cloudflare_production_rollout.md`](../../docs/review-checklists/cloudflare_production_rollout.md)
