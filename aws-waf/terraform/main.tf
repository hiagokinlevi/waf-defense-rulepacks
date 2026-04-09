# =============================================================================
# AWS WAFv2 WebACL — Terraform Module
# k1n-waf-defense-rulepacks
# =============================================================================
# Deploys the k1N baseline AWS WAFv2 WebACL with managed rule groups and
# custom rules for login rate limiting and admin path restriction.
#
# Prerequisites:
#   - Terraform >= 1.5
#   - AWS provider ~> 5.0
#   - IAM permissions: wafv2:*, cloudwatch:PutMetricData, logs:*
#
# Usage:
#   terraform init
#   terraform plan -var="resource_arn=arn:aws:elasticloadbalancing:..."
#   # Deploy in count mode first (enforce_mode = false)
#   terraform apply -var="resource_arn=..." -var="enforce_mode=false"
#   # After validating no false positives, switch to enforce mode
#   terraform apply -var="resource_arn=..." -var="enforce_mode=true"
# =============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.5"
}

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------

variable "region" {
  description = "AWS region for deployment. Use us-east-1 for CloudFront distributions."
  type        = string
  default     = "us-east-1"
}

variable "resource_arn" {
  description = "ARN of the ALB, API Gateway, or CloudFront distribution to associate with the WebACL"
  type        = string
}

variable "enforce_mode" {
  description = "Set to true to enforce blocking. Set to false for count-only (log) mode."
  type        = bool
  default     = false # Start in log mode — validate before enforcing
}

variable "admin_allowlist_cidrs" {
  description = "List of CIDR blocks allowed to access admin paths"
  type        = list(string)
  default     = ["192.168.0.0/16", "10.0.0.0/8"] # Replace with your actual CIDRs
}

variable "environment" {
  description = "Environment name (e.g., prod, staging) — used for resource naming and tagging"
  type        = string
  default     = "prod"
}

# ---------------------------------------------------------------------------
# Local variables
# ---------------------------------------------------------------------------

locals {
  # Use Count action in log mode, Block in enforce mode
  # Count mode allows all requests through while logging rule matches
  override_action = var.enforce_mode ? "none" : "count"
  name_prefix     = "k1n-${var.environment}"
}

# ---------------------------------------------------------------------------
# IP Set for Admin Allowlist
# ---------------------------------------------------------------------------
# Create an IP set for admin path restriction. Update with your actual IP ranges.
resource "aws_wafv2_ip_set" "admin_allowlist" {
  name               = "${local.name_prefix}-admin-allowlist"
  description        = "Allowlisted IPs for admin path access — k1N pack v1.0"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = var.admin_allowlist_cidrs

  tags = {
    Project = "k1n-waf-defense-rulepacks"
    Pack    = "admin-protection"
    Managed = "terraform"
  }
}

# ---------------------------------------------------------------------------
# CloudWatch Log Group for WAF Logs
# ---------------------------------------------------------------------------
# WAF log group must use the prefix "aws-waf-logs-"
resource "aws_cloudwatch_log_group" "waf_logs" {
  name              = "aws-waf-logs-${local.name_prefix}"
  retention_in_days = 90 # Retain logs for 90 days — adjust for compliance requirements

  tags = {
    Project = "k1n-waf-defense-rulepacks"
    Managed = "terraform"
  }
}

# ---------------------------------------------------------------------------
# WAFv2 WebACL
# ---------------------------------------------------------------------------
resource "aws_wafv2_web_acl" "k1n_baseline" {
  name        = "${local.name_prefix}-baseline-webacl"
  description = "k1N baseline WebACL with managed rule groups and custom rules — v1.0"
  scope       = "REGIONAL"

  default_action {
    allow {} # Default allow — explicit denies in rules below
  }

  # --- Custom Rule 1: Login Rate Limit ---
  # Evaluated first (priority 1) to catch brute force before managed rules
  rule {
    name     = "k1n-LoginRateLimit"
    priority = 1

    statement {
      rate_based_statement {
        limit              = 100  # 100 requests per IP per 5 minutes — tune as needed
        aggregate_key_type = "IP"
        evaluation_window_sec = 300

        scope_down_statement {
          and_statement {
            statement {
              byte_match_statement {
                search_string         = "/login"
                positional_constraint = "CONTAINS"
                field_to_match {
                  uri_path {}
                }
                text_transformation {
                  priority = 0
                  type     = "LOWERCASE"
                }
              }
            }
            statement {
              byte_match_statement {
                search_string         = "POST"
                positional_constraint = "EXACTLY"
                field_to_match {
                  method {}
                }
                text_transformation {
                  priority = 0
                  type     = "NONE"
                }
              }
            }
          }
        }
      }
    }

    action {
      block {
        custom_response {
          response_code = 429
          response_header {
            name  = "Content-Type"
            value = "application/json"
          }
        }
      }
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "k1nLoginRateLimit"
    }
  }

  # --- Custom Rule 2: Admin Path Restriction ---
  # Block admin paths from non-allowlisted IPs
  rule {
    name     = "k1n-AdminPathRestriction"
    priority = 2

    statement {
      and_statement {
        statement {
          byte_match_statement {
            search_string         = "/admin"
            positional_constraint = "STARTS_WITH"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
        statement {
          not_statement {
            statement {
              ip_set_reference_statement {
                arn = aws_wafv2_ip_set.admin_allowlist.arn
              }
            }
          }
        }
      }
    }

    action {
      block {} # Always block unauthorized admin access
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "k1nAdminPathRestriction"
    }
  }

  # --- Managed Rule Group: AWS Common Rule Set ---
  # Covers OWASP Top 10 common attack patterns
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 10

    override_action {
      dynamic "none" {
        for_each = var.enforce_mode ? [1] : []
        content {}
      }
      dynamic "count" {
        for_each = var.enforce_mode ? [] : [1]
        content {} # Count mode — log only, do not block
      }
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"

        # Exclude rules that commonly cause false positives — re-enable after testing
        rule_action_override {
          name = "SizeRestrictions_BODY"
          action_to_use {
            count {} # Count instead of block — validate before enforcing
          }
        }
      }
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesCommonRuleSet"
    }
  }

  # --- Managed Rule Group: SQLi Rule Set ---
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 20

    override_action {
      dynamic "none" {
        for_each = var.enforce_mode ? [1] : []
        content {}
      }
      dynamic "count" {
        for_each = var.enforce_mode ? [] : [1]
        content {}
      }
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesSQLiRuleSet"
      }
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesSQLiRuleSet"
    }
  }

  # --- Managed Rule Group: Known Bad Inputs ---
  # Includes Log4Shell, SSRF, and other known exploit patterns
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 30

    override_action {
      dynamic "none" {
        for_each = var.enforce_mode ? [1] : []
        content {}
      }
      dynamic "count" {
        for_each = var.enforce_mode ? [] : [1]
        content {}
      }
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
      }
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesKnownBadInputsRuleSet"
    }
  }

  # --- Managed Rule Group: IP Reputation List ---
  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 40

    override_action {
      dynamic "none" {
        for_each = var.enforce_mode ? [1] : []
        content {}
      }
      dynamic "count" {
        for_each = var.enforce_mode ? [] : [1]
        content {}
      }
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesAmazonIpReputationList"
      }
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesAmazonIpReputationList"
    }
  }

  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name_prefix}-baseline-webacl"
  }

  tags = {
    Project     = "k1n-waf-defense-rulepacks"
    Environment = var.environment
    EnforceMode = tostring(var.enforce_mode)
    Managed     = "terraform"
  }
}

# ---------------------------------------------------------------------------
# Associate WebACL with the target resource (ALB, API Gateway, etc.)
# ---------------------------------------------------------------------------
resource "aws_wafv2_web_acl_association" "k1n_association" {
  resource_arn = var.resource_arn
  web_acl_arn  = aws_wafv2_web_acl.k1n_baseline.arn
}

# ---------------------------------------------------------------------------
# Enable WAF Logging to CloudWatch
# ---------------------------------------------------------------------------
resource "aws_wafv2_web_acl_logging_configuration" "k1n_logging" {
  log_destination_configs = [aws_cloudwatch_log_group.waf_logs.arn]
  resource_arn            = aws_wafv2_web_acl.k1n_baseline.arn

  # Only log requests that are blocked or would be blocked — reduce log volume
  logging_filter {
    default_behavior = "DROP" # Drop sampled allow logs; only keep block/count logs

    filter {
      behavior = "KEEP"
      condition {
        action_condition {
          action = "BLOCK"
        }
      }
      requirement = "MEETS_ANY"
    }

    filter {
      behavior = "KEEP"
      condition {
        action_condition {
          action = "COUNT"
        }
      }
      requirement = "MEETS_ANY"
    }
  }
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

output "web_acl_arn" {
  description = "ARN of the deployed k1N baseline WebACL"
  value       = aws_wafv2_web_acl.k1n_baseline.arn
}

output "web_acl_id" {
  description = "ID of the deployed k1N baseline WebACL"
  value       = aws_wafv2_web_acl.k1n_baseline.id
}

output "admin_ip_set_arn" {
  description = "ARN of the admin allowlist IP set"
  value       = aws_wafv2_ip_set.admin_allowlist.arn
}

output "log_group_name" {
  description = "CloudWatch Log Group name for WAF logs"
  value       = aws_cloudwatch_log_group.waf_logs.name
}
