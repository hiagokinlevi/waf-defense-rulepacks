# Cloudflare API Security Rollout Guide

This guide focuses on Cloudflare deployments for APIs, GraphQL surfaces, login flows, and webhook endpoints.

## Recommended Pack Set

- [`cloudflare/waf-rules/block_api_abuse_excessive_data_exposure.json`](../../cloudflare/waf-rules/block_api_abuse_excessive_data_exposure.json)
- [`cloudflare/waf-rules/protect_graphql_introspection.json`](../../cloudflare/waf-rules/protect_graphql_introspection.json)
- [`cloudflare/waf-rules/protect_debug_and_actuator_endpoints.json`](../../cloudflare/waf-rules/protect_debug_and_actuator_endpoints.json)
- [`cloudflare/rate-limits/api_rate_limit.json`](../../cloudflare/rate-limits/api_rate_limit.json)
- [`cloudflare/rate-limits/password_reset_rate_limit.json`](../../cloudflare/rate-limits/password_reset_rate_limit.json)
- [`cloudflare/rate-limits/webhook_burst_rate_limit.json`](../../cloudflare/rate-limits/webhook_burst_rate_limit.json)
- [`cloudflare/bot-rules/login_js_challenge_low_score.json`](../../cloudflare/bot-rules/login_js_challenge_low_score.json)

## Rollout Pattern

1. Start with visibility-only rules for GraphQL, API abuse, and webhooks.
2. Add path-specific rate limits for login and recovery.
3. Challenge low bot-score browser traffic only on browser login routes.
4. Lock down debug and actuator paths once operational exceptions are known.

## What to Avoid

- Do not apply JS or managed challenges to machine-to-machine APIs without explicit client testing.
- Do not reuse the same threshold for `/api/*`, `/login`, and `/webhooks`.
- Do not hide false positives by weakening a global expression when a narrow exclusion is enough.

## Metrics to Review Before Enforcement

- Top matched API paths
- Top source ASNs and countries
- Solve rate for browser challenges
- Event counts on `/graphql`
- Webhook retry bursts by provider path

## Practical Recommendation

Treat Cloudflare API protection as a bundle of small packs, not one giant rule. Teams tune faster and with less production risk when each path family has its own rule and owner.
