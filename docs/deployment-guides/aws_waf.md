# AWS WAF Deployment Guide

This guide covers deploying waf-defense-rulepacks to AWS WAFv2, using either the AWS CLI or Terraform.

## Prerequisites

- AWS account with permissions: `wafv2:*`, `iam:CreateServiceLinkedRole` (for CloudWatch integration)
- A target resource: Application Load Balancer, API Gateway REST API, API Gateway v2, or CloudFront distribution
- For CloudFront distributions, deploy the WebACL in `us-east-1` (global scope)

## Deployment Workflow

```
Create IP Sets → Create WebACL in Count mode → Associate with resource → Validate (72h) → Switch to enforcement
```

---

## Method 1: AWS CLI

### Step 1: Create Admin IP Set

```bash
# Replace CIDRs with your actual office/VPN IP ranges
aws wafv2 create-ip-set \
  --name "k1n-admin-allowlist" \
  --scope REGIONAL \
  --ip-address-version IPV4 \
  --addresses "10.0.0.0/8" "192.168.0.0/16" \
  --region us-east-1
```

Note the `ARN` from the output — you'll need it for the custom rules.

### Optional: Attach the Standalone IP Reputation Pack

Use `aws-waf/rules/ip_reputation_managed_group.json` when you want the AWS
managed IP reputation rule group without adopting the full baseline WebACL. The
pack starts with `OverrideAction: Count` so security teams can review sampled
requests before enforcing blocks.

Before switching `OverrideAction` to `None`, review:

- trusted partner, uptime monitor, and corporate NAT CIDRs that need allow-listing
- CloudWatch `CountedRequests` for the `k1nAwsIpReputationList` metric
- sampled requests against login, checkout, API token, and admin paths

### Step 2: Create WebACL in Count Mode

Update `aws-waf/managed_rule_groups.json` to use `OverrideAction: Count` for all managed rule groups (log-only mode).

```bash
aws wafv2 create-web-acl \
  --cli-input-json file://aws-waf/managed_rule_groups.json \
  --region us-east-1
```

### Step 3: Associate with Your Resource

```bash
# Replace with your actual WebACL ARN and resource ARN
aws wafv2 associate-web-acl \
  --web-acl-arn "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/k1n-baseline-web-acl/..." \
  --resource-arn "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/..." \
  --region us-east-1
```

### Step 4: Enable WAF Logging

```bash
# Create a log group (must start with aws-waf-logs-)
aws logs create-log-group \
  --log-group-name "aws-waf-logs-k1n-baseline" \
  --region us-east-1

# Enable logging on the WebACL
aws wafv2 put-logging-configuration \
  --logging-configuration '{
    "ResourceArn": "arn:aws:wafv2:...",
    "LogDestinationConfigs": ["arn:aws:logs:us-east-1:123456789012:log-group:aws-waf-logs-k1n-baseline"]
  }' \
  --region us-east-1
```

### Step 5: Validate and Switch to Enforcement

After 72 hours of Count mode:

1. Check CloudWatch Metrics for each managed rule group
2. Review sampled requests for false positives:
   ```bash
   aws wafv2 get-sampled-requests \
     --web-acl-arn "..." \
     --rule-metric-name "AWSManagedRulesCommonRuleSet" \
     --scope REGIONAL \
     --time-window '{"StartTime": "2026-01-01T00:00:00Z", "EndTime": "2026-01-04T00:00:00Z"}' \
     --max-items 100 \
     --region us-east-1
   ```
3. If no false positives, switch `OverrideAction` from `Count` to `None` for each rule group

---

## Method 2: Terraform

See `aws-waf/terraform/main.tf` for the full Terraform module.

### Quick Start

```bash
# 1. Configure AWS credentials
aws configure

# 2. Initialize Terraform
cd aws-waf/terraform
terraform init

# 3. Plan in log mode (enforce_mode = false)
terraform plan \
  -var="resource_arn=arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/..." \
  -var="enforce_mode=false" \
  -var="environment=prod"

# 4. Apply in log mode
terraform apply \
  -var="resource_arn=..." \
  -var="enforce_mode=false" \
  -var="environment=prod"

# 5. After 72h validation, switch to enforce mode
terraform apply \
  -var="resource_arn=..." \
  -var="enforce_mode=true" \
  -var="environment=prod"
```

---

## Pricing Considerations

AWS WAF pricing (as of 2026, check current pricing at aws.amazon.com/waf/pricing):
- WebACL: $5/month
- Per rule: $1/month
- Per million requests: $0.60

Managed rule groups add additional cost per rule group. The 5 managed rule groups in `managed_rule_groups.json` represent approximately $30-50/month in rule group fees plus request processing fees.

---

## Monitoring Setup

### CloudWatch Metrics

AWS WAF publishes metrics to CloudWatch under the `AWS/WAFV2` namespace:
- `AllowedRequests` — requests allowed by the WebACL
- `BlockedRequests` — requests blocked by the WebACL
- `CountedRequests` — requests matched by count-mode rules

Create alarms:

```bash
# Alert if blocked requests exceed 1000 in 5 minutes (spike indicator)
aws cloudwatch put-metric-alarm \
  --alarm-name "k1n-waf-block-spike" \
  --metric-name "BlockedRequests" \
  --namespace "AWS/WAFV2" \
  --statistic "Sum" \
  --period 300 \
  --threshold 1000 \
  --comparison-operator "GreaterThanThreshold" \
  --dimensions "Name=WebACL,Value=k1n-prod-baseline-webacl" "Name=Region,Value=us-east-1" "Name=Rule,Value=ALL" \
  --evaluation-periods 1 \
  --alarm-actions "arn:aws:sns:us-east-1:123456789012:security-alerts"
```

### Log Insights Queries

```sql
-- Top blocked URIs in the last 24 hours
fields httpRequest.uri
| filter action = "BLOCK"
| stats count(*) as blockCount by httpRequest.uri
| sort blockCount desc
| limit 20
```

---

## Recommended Deep-Dive Material

For broader AWS WAF coverage beyond the initial baseline, continue with:

- [`aws-waf/examples/protect_alb_api.md`](../../aws-waf/examples/protect_alb_api.md)
- [`aws-waf/examples/protect_cloudfront_app.md`](../../aws-waf/examples/protect_cloudfront_app.md)
- [`docs/deployment-guides/aws_waf_api_protection.md`](aws_waf_api_protection.md)
- [`docs/review-checklists/aws_waf_production_rollout.md`](../review-checklists/aws_waf_production_rollout.md)
- [`training/tutorials/aws_waf_managed_rules_baseline.md`](../../training/tutorials/aws_waf_managed_rules_baseline.md)
