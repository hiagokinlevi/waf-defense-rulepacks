# Example: Protecting an ALB-Backed API with AWS WAF

This example shows how to layer AWS WAF packs in front of an Application Load Balancer that exposes browser login flows, public APIs, and GraphQL endpoints.

## Target Profile

- Resource type: ALB
- Public API: `/api/*`
- GraphQL: `/graphql`
- Admin: `/admin/*`
- Password reset: `/forgot-password`
- Diagnostics: `/actuator/*`, `/metrics`, `/healthz`

## Recommended Rule Order

1. [`aws-waf/rules/admin_surface_allowlist.json`](../rules/admin_surface_allowlist.json)
2. [`aws-waf/rules/password_reset_rate_limit.json`](../rules/password_reset_rate_limit.json)
3. [`aws-waf/rules/graphql_introspection_guard.json`](../rules/graphql_introspection_guard.json)
4. [`aws-waf/rules/api_burst_rate_limit.json`](../rules/api_burst_rate_limit.json)
5. [`aws-waf/rules/debug_endpoint_restriction.json`](../rules/debug_endpoint_restriction.json)
6. [`aws-waf/managed_rule_groups.json`](../managed_rule_groups.json)
7. [`aws-waf/rules/bot_control_managed_group.json`](../rules/bot_control_managed_group.json)

## Rollout Notes

- Use `Count` mode for recovery, GraphQL, API burst, and bot-control rules first.
- Use `Block` immediately for admin and debug surfaces only after you have validated trusted IP sets and monitoring paths.
- Review CloudWatch metrics and sampled requests daily during the first week.

## ALB-Specific Considerations

- Confirm body inspection limits for the ALB-associated WebACL.
- Keep `/api/internal/*` and health checks out of general burst rules.
- Document all IP sets used for allowlists and revisit them monthly.

## Success Criteria

- GraphQL introspection requests are visible and explainable.
- Admin and debug surfaces are internet-inaccessible except from trusted ranges.
- Password reset and public API bursts show measurable baselines before enforcement.
- Managed rule groups remain below your false-positive tolerance before block mode.
