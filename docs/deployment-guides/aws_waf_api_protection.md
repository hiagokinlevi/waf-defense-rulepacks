# AWS WAF API Protection Guide

This guide focuses on ALB, API Gateway, and CloudFront deployments where AWS WAF protects APIs, recovery flows, GraphQL endpoints, and operational paths.

## Recommended Pack Set

- [`aws-waf/managed_rule_groups.json`](../../aws-waf/managed_rule_groups.json)
- [`aws-waf/rules/graphql_introspection_guard.json`](../../aws-waf/rules/graphql_introspection_guard.json)
- [`aws-waf/rules/password_reset_rate_limit.json`](../../aws-waf/rules/password_reset_rate_limit.json)
- [`aws-waf/rules/api_burst_rate_limit.json`](../../aws-waf/rules/api_burst_rate_limit.json)
- [`aws-waf/rules/debug_endpoint_restriction.json`](../../aws-waf/rules/debug_endpoint_restriction.json)
- [`aws-waf/rules/admin_surface_allowlist.json`](../../aws-waf/rules/admin_surface_allowlist.json)
- [`aws-waf/rules/bot_control_managed_group.json`](../../aws-waf/rules/bot_control_managed_group.json)

## Suggested Rule Order

Place custom rules before broad managed rule groups when they represent higher-confidence business controls:

1. Admin and debug surface restrictions
2. Recovery and GraphQL visibility
3. API burst visibility
4. Managed rule groups
5. Bot Control

## Resource-Specific Notes

### ALB

- Use REGIONAL scope.
- Confirm body inspection limits for GraphQL or JSON-heavy requests.
- Keep internal API paths and health checks out of general burst rules.

### API Gateway

- Protect auth, reset, and GraphQL routes with dedicated rules.
- Keep stage-specific paths visible in logs so you can separate dev from prod behavior.

### CloudFront

- Manage the WebACL in `us-east-1`.
- Expect more global noise from anonymous IPs and crawlers.

## Promotion Strategy

- Count mode for all new visibility or rate-based rules
- Review sampled requests daily
- Move only one control family to block mode at a time
- Keep rollback notes per rule, not just per WebACL
