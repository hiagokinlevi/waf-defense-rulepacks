# Example: Protecting a CloudFront-Fronted Application with AWS WAF

This example focuses on a CloudFront distribution serving a web frontend and regional APIs behind origin services.

## Why CloudFront Changes the Rollout

- CloudFront WebACLs must be managed in `us-east-1`.
- Global traffic means geographies, crawlers, and verification services vary more than on a regional ALB.
- Bot and anonymous-IP controls usually show more matches, especially on marketing or login surfaces.

## Suggested Baseline

1. Managed rule groups from [`aws-waf/managed_rule_groups.json`](../managed_rule_groups.json)
2. [`aws-waf/rules/bot_control_managed_group.json`](../rules/bot_control_managed_group.json)
3. [`aws-waf/rules/admin_surface_allowlist.json`](../rules/admin_surface_allowlist.json)
4. [`aws-waf/rules/debug_endpoint_restriction.json`](../rules/debug_endpoint_restriction.json)
5. [`aws-waf/rules/graphql_introspection_guard.json`](../rules/graphql_introspection_guard.json) if GraphQL is exposed

## Tuning Priorities

- Separate human traffic, SEO crawlers, and partner automation before enforcing bot rules.
- Keep CloudFront origin health checks, synthetic monitoring, and static asset paths outside sensitive rules.
- Review sampled requests from `AWSManagedRulesAnonymousIpList` to avoid breaking legitimate provider-based traffic.

## Production Advice

Move in this order:

1. Managed groups in Count mode
2. Bot Control in Count mode
3. Admin/debug restrictions with validated allowlists
4. GraphQL and recovery protections
5. Controlled promotion to Block or Challenge after one week of review
