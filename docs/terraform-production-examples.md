# Terraform Deployment Examples (Production)

This guide provides **production-oriented Terraform examples** for deploying the repository's rulepacks on:

- Cloudflare WAF
- AWS WAFv2
- Azure WAF (Application Gateway + Front Door)

> These examples are intentionally minimal and safe-by-default patterns. Validate in staging, enable logging/monitoring, and tune before enforcing blocks.

---

## 1) Cloudflare WAF (Zone Ruleset + Rate Limit)

This pattern applies custom WAF expressions and a rate-limit rule at the zone level.

```hcl
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

variable "cloudflare_api_token" {
  type      = string
  sensitive = true
}

variable "zone_id" {
  type = string
}

# Example: custom ruleset phase for HTTP request firewall custom rules
resource "cloudflare_ruleset" "custom_waf" {
  zone_id = var.zone_id
  name    = "prod-custom-waf"
  kind    = "zone"
  phase   = "http_request_firewall_custom"

  rules {
    action      = "block"
    expression  = "(http.request.uri.path contains \"/admin\" and not ip.src in {203.0.113.0/24})"
    description = "Protect admin path"
    enabled     = true
  }

  rules {
    action      = "managed_challenge"
    expression  = "(cf.threat_score gt 20)"
    description = "Challenge elevated threat score"
    enabled     = true
  }
}

# Example: rate limiting login attempts
resource "cloudflare_ruleset" "rate_limit" {
  zone_id = var.zone_id
  name    = "prod-login-rate-limit"
  kind    = "zone"
  phase   = "http_ratelimit"

  rules {
    action = "block"
    ratelimit {
      characteristics     = ["ip.src", "http.request.uri.path"]
      period              = 60
      requests_per_period = 10
      mitigation_timeout  = 600
    }

    expression  = "(http.request.uri.path eq \"/login\" and http.request.method eq \"POST\")"
    description = "Rate limit login brute force"
    enabled     = true
  }
}
```

**Production notes**
- Start sensitive rules with `managed_challenge` before `block`.
- Keep emergency allowlist CIDRs in variables and review monthly.
- Pair with Cloudflare Security Events alerting.

---

## 2) AWS WAFv2 (Regional Web ACL + Managed + Custom)

This pattern creates a regional Web ACL, attaches AWS managed protections, and includes a custom rate-based rule.

```hcl
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "name_prefix" {
  type    = string
  default = "prod-app"
}

resource "aws_cloudwatch_log_group" "waf" {
  name              = "/aws/wafv2/${var.name_prefix}"
  retention_in_days = 30
}

resource "aws_wafv2_web_acl" "this" {
  name  = "${var.name_prefix}-web-acl"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "AWS-CommonRuleSet"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "awsCommon"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "LoginRateLimit"
    priority = 20

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 100
        aggregate_key_type = "IP"

        scope_down_statement {
          byte_match_statement {
            positional_constraint = "EXACTLY"
            search_string         = "/login"

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "NONE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "loginRateLimit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}WebAcl"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_logging_configuration" "this" {
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
  resource_arn            = aws_wafv2_web_acl.this.arn
}
```

**Production notes**
- Add additional managed groups (KnownBadInputs, IPReputation) in monitor-first mode.
- Tune `limit` based on peak login RPS and NATed user populations.
- Associate this ACL to ALB / API Gateway / AppSync in your environment-specific stack.

---

## 3) Azure WAF (Application Gateway Policy)

This pattern creates a WAF policy in Prevention mode with OWASP rules and custom match/rate rules.

```hcl
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

variable "resource_group_name" {
  type = string
}

variable "location" {
  type = string
}

resource "azurerm_web_application_firewall_policy" "appgw" {
  name                = "prod-appgw-waf-policy"
  resource_group_name = var.resource_group_name
  location            = var.location

  policy_settings {
    enabled                     = true
    mode                        = "Prevention"
    request_body_check          = true
    file_upload_limit_in_mb     = 100
    max_request_body_size_in_kb = 128
  }

  managed_rules {
    managed_rule_set {
      type    = "OWASP"
      version = "3.2"
    }
  }

  custom_rules {
    name      = "BlockAdminOutsideCorp"
    priority  = 1
    rule_type = "MatchRule"
    action    = "Block"

    match_conditions {
      operator           = "Contains"
      negation_condition = false
      match_values       = ["/admin"]

      match_variables {
        variable_name = "RequestUri"
      }
    }
  }
}
```

**Production notes**
- Start in `Detection` in pre-prod, then shift to `Prevention` after tuning.
- Use exclusions for known noisy parameters rather than disabling full rule groups.
- Enable diagnostics to Log Analytics and alert on anomaly spikes.

---

## 4) Azure Front Door WAF Policy (Optional Pattern)

```hcl
resource "azurerm_cdn_frontdoor_firewall_policy" "fd" {
  name                = "prod-frontdoor-waf"
  resource_group_name = var.resource_group_name
  sku_name            = "Premium_AzureFrontDoor"
  enabled             = true
  mode                = "Prevention"

  managed_rule {
    type    = "DefaultRuleSet"
    version = "1.0"
    action  = "Block"
  }

  custom_rule {
    name                           = "RateLimitLogin"
    enabled                        = true
    priority                       = 1
    type                           = "RateLimitRule"
    rate_limit_threshold           = 100
    rate_limit_duration_in_minutes = 1
    action                         = "Block"

    match_condition {
      match_variable   = "RequestUri"
      operator         = "Contains"
      match_values     = ["/login"]
      negation_condition = false
    }
  }
}
```

---

## Operational Checklist (All Vendors)

- Deploy via environment workspaces (`dev`, `staging`, `prod`) and promote only validated changes.
- Keep break-glass allowlists versioned and time-bounded.
- Enable logs before enforcing hard blocks.
- Set SLO-driven alerts (blocked surge, allowed anomaly, challenge spike).
- Review false positives weekly during initial rollout.
