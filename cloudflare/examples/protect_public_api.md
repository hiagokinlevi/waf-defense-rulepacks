# Example: Protecting a Public API with Cloudflare

This example shows a practical Cloudflare rollout for an internet-facing API that serves browser clients, partner integrations, and mobile traffic.

## Target Profile

- Public API paths: `/api/*`
- GraphQL path: `/graphql`
- Login flow: `/api/auth/login`
- Password recovery: `/api/auth/forgot-password`
- Webhooks: `/api/webhooks/provider`
- Trusted actors: CI, partner IP ranges, and internal VPN egress

## Recommended Pack Stack

1. [`cloudflare/waf-rules/protect_graphql_introspection.json`](../waf-rules/protect_graphql_introspection.json)
2. [`cloudflare/waf-rules/block_api_abuse_excessive_data_exposure.json`](../waf-rules/block_api_abuse_excessive_data_exposure.json)
3. [`cloudflare/rate-limits/api_rate_limit.json`](../rate-limits/api_rate_limit.json)
4. [`cloudflare/rate-limits/password_reset_rate_limit.json`](../rate-limits/password_reset_rate_limit.json)
5. [`cloudflare/rate-limits/webhook_burst_rate_limit.json`](../rate-limits/webhook_burst_rate_limit.json)
6. [`cloudflare/waf-rules/protect_debug_and_actuator_endpoints.json`](../waf-rules/protect_debug_and_actuator_endpoints.json)

## Rollout Sequence

### Phase 1: Visibility

- Deploy GraphQL introspection and API abuse rules in `log` mode.
- Deploy webhook burst protection in `log` mode.
- Keep password reset protection in `managed_challenge` only after reviewing two days of recovery traffic.

### Phase 2: Authentication Hardening

- Deploy the login rate limit and low bot-score login challenge together.
- Exclude API token endpoints, mobile SDK endpoints, and machine-to-machine auth flows from browser-oriented challenge rules.

### Phase 3: Operational Surface Lockdown

- Deploy the debug and actuator endpoint restriction rule in `block` mode if your observability stack already uses private or authenticated paths.
- If not, deploy in `log` mode first and inventory every legitimate consumer before enforcing.

## What to Exclude Carefully

- CI or smoke-test traffic that still targets production
- Partner integrations that share NAT space
- Schema tooling used by approved release automation
- Signed webhook providers with known retry patterns

## What to Watch

- Security Events by path and ASN
- Top matched rules on `/graphql`
- Reset/recovery spikes by source country
- Repeated bot-score challenges on `/api/auth/login`
- Burst matches on `/api/webhooks/*`

## Operational Note

Cloudflare is strongest when API rules are scoped narrowly. Avoid one giant expression for every path. Separate authentication, GraphQL, operational endpoints, and webhook traffic so tuning remains understandable.
