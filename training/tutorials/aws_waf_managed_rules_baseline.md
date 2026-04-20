# Tutorial: Building an AWS WAF Managed Rule Baseline

This tutorial walks through building a production-ready AWS WAF baseline around managed rule groups plus a few focused custom controls.

## Goal

By the end, you will have:

- a managed-rule WebACL in Count mode
- one admin allowlist rule
- one recovery-flow rate limit
- one GraphQL visibility rule
- a clear promotion checklist

## Start Here

Review these files:

- [`aws-waf/managed_rule_groups.json`](../../aws-waf/managed_rule_groups.json)
- [`aws-waf/rules/admin_surface_allowlist.json`](../../aws-waf/rules/admin_surface_allowlist.json)
- [`aws-waf/rules/password_reset_rate_limit.json`](../../aws-waf/rules/password_reset_rate_limit.json)
- [`aws-waf/rules/graphql_introspection_guard.json`](../../aws-waf/rules/graphql_introspection_guard.json)

## Step 1: Build Visibility First

Create the WebACL with managed groups in Count mode. Add the recovery and GraphQL rules in Count mode as well. The admin allowlist can start in Block mode only if the IP set is already verified.

## Step 2: Review Sampled Requests

For each rule, answer:

- Is this path expected?
- Is the source ASN expected?
- Is this a trusted integration or opportunistic scan?
- Would blocking this request hurt a business workflow?

## Step 3: Promote One Family at a Time

Promote in this order:

1. admin surface restriction
2. debug and metrics restriction
3. recovery-flow rate limit
4. GraphQL introspection guard
5. managed groups with validated exclusions

## Step 4: Write the Rollback Notes

Document:

- rule name
- current action
- rollback action
- owner
- conditions for immediate rollback

The habit matters as much as the JSON.
