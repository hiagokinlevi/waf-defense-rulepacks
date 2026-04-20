# Cloudflare Production Rollout Checklist

Use this checklist before promoting Cloudflare WAF, rate-limit, and bot rules from observation to enforcement.

## Rule Quality

- [ ] Every rule has a clear business owner
- [ ] Every rule has path scope documented
- [ ] Every exclusion is explicit and justified
- [ ] API and browser flows are separated

## Operational Readiness

- [ ] Security Events are reviewed daily
- [ ] Alert thresholds are defined for event spikes
- [ ] Partner and CI source ranges are documented
- [ ] Rollback steps are written per rule

## High-Risk Paths

- [ ] `/login` and `/auth/*` have separate tuning from general APIs
- [ ] `/graphql` introspection has a production decision documented
- [ ] `/webhooks` and `/callbacks` have provider-specific review notes
- [ ] `/actuator`, `/metrics`, `/debug`, and `/internal` are either blocked or deliberately justified

## Promotion Gate

- [ ] Rule stayed in log or challenge mode long enough to establish a baseline
- [ ] Top matched IPs and ASNs were reviewed
- [ ] False positives were tested with real application owners
- [ ] The team can name the exact condition that would trigger rollback
