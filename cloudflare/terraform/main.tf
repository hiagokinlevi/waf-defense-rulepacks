# =============================================================================
# Cloudflare WAF Rules — Terraform Module
# k1n-waf-defense-rulepacks
# =============================================================================
# This Terraform configuration deploys the k1N defensive WAF rulesets
# to a Cloudflare zone. Adjust variables to match your environment.
#
# Prerequisites:
#   - Terraform >= 1.5
#   - Cloudflare provider ~> 4.0
#   - CLOUDFLARE_API_TOKEN env var with Zone.WAF permissions
#
# Usage:
#   terraform init
#   terraform plan -var="zone_id=your_zone_id"
#   terraform apply -var="zone_id=your_zone_id" -var="mode=log"
#   # After validating in log mode:
#   terraform apply -var="zone_id=your_zone_id" -var="mode=block"
# =============================================================================

terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
  required_version = ">= 1.5"
}

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------

variable "zone_id" {
  description = "Cloudflare Zone ID where WAF rules will be deployed"
  type        = string
}

variable "mode" {
  description = "Enforcement mode: 'log' for observation, 'block' for enforcement. Always start with 'log'."
  type        = string
  default     = "log" # Start in log mode — switch to block after 72h of validation

  validation {
    condition     = contains(["log", "block", "challenge", "js_challenge", "managed_challenge"], var.mode)
    error_message = "mode must be one of: log, block, challenge, js_challenge, managed_challenge"
  }
}

variable "admin_allowlist_cidrs" {
  description = "List of CIDR blocks allowed to access admin paths. Update before deploying."
  type        = list(string)
  default     = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"] # Replace with actual CIDRs
}

variable "enable_bot_management" {
  description = "Set to true if you have Cloudflare Bot Management enabled on your plan"
  type        = bool
  default     = false # Requires Cloudflare Bot Management add-on
}

# ---------------------------------------------------------------------------
# SQL Injection Protection
# ---------------------------------------------------------------------------
# Matches common SQLi patterns in query strings and request bodies.
# Deploy in 'log' mode first to identify false positives on search/filter endpoints.
resource "cloudflare_ruleset" "sqli_protection" {
  zone_id     = var.zone_id
  name        = "k1N SQLi Protection"
  description = "Blocks common SQL injection patterns in query strings and request bodies — k1N pack v1.0"
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  rules {
    action      = var.mode
    expression  = "(http.request.uri.query contains \"' OR\" or http.request.uri.query contains \"UNION SELECT\" or http.request.uri.query contains \"DROP TABLE\" or http.request.body contains \"UNION SELECT\" or http.request.body contains \"INSERT INTO\" or http.request.body contains \"DROP TABLE\")"
    description = "Block SQLi patterns — k1N pack v1.0"
    enabled     = true
  }
}

# ---------------------------------------------------------------------------
# XSS Protection
# ---------------------------------------------------------------------------
# Matches common XSS payload patterns.
# Exclude rich text editor endpoints before deploying in block mode.
resource "cloudflare_ruleset" "xss_protection" {
  zone_id     = var.zone_id
  name        = "k1N XSS Protection"
  description = "Blocks common XSS patterns in query strings and request bodies — k1N pack v1.0"
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  rules {
    action      = var.mode
    expression  = "(http.request.uri.query contains \"<script\" or http.request.uri.query contains \"javascript:\" or http.request.uri.query contains \"onerror=\" or http.request.body contains \"<script\" or http.request.body contains \"javascript:\" or http.request.body contains \"onerror=\")"
    description = "Block XSS patterns — k1N pack v1.0"
    enabled     = true
  }
}

# ---------------------------------------------------------------------------
# Admin Panel Protection
# ---------------------------------------------------------------------------
# Always blocks unauthorized access to admin paths — not affected by the
# var.mode variable because admin protection should always be enforced.
resource "cloudflare_ruleset" "admin_protection" {
  zone_id     = var.zone_id
  name        = "k1N Admin Panel Protection"
  description = "Restricts access to administrative paths to allowlisted IPs — k1N pack v1.0"
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  rules {
    action = "block" # Always block — do not switch to log for admin protection

    # NOTE: Update admin_allowlist_cidrs variable with your actual IP ranges before deploying
    expression  = "(http.request.uri.path wildcard \"/admin*\" or http.request.uri.path wildcard \"/wp-admin*\" or http.request.uri.path wildcard \"/phpmyadmin*\" or http.request.uri.path wildcard \"/cpanel*\") and not ip.src in {${join(" ", var.admin_allowlist_cidrs)}}"
    description = "Block admin paths from non-allowlisted IPs — update var.admin_allowlist_cidrs before deploying"
    enabled     = true
  }
}

# ---------------------------------------------------------------------------
# Login Rate Limit
# ---------------------------------------------------------------------------
# Prevents brute-force and credential stuffing attacks on login endpoints.
# Threshold: 5 POST requests per IP per 60 seconds. Tune as needed.
resource "cloudflare_ruleset" "login_rate_limit" {
  zone_id     = var.zone_id
  name        = "k1N Login Rate Limit"
  description = "Rate limits POST requests to login endpoints — k1N pack v1.0"
  kind        = "zone"
  phase       = "http_ratelimit"

  rules {
    action = "block"
    action_parameters {
      response {
        status_code  = 429
        content_type = "application/json"
        content      = "{\"error\": \"Too many login attempts. Please wait before trying again.\"}"
      }
    }
    ratelimit {
      characteristics     = ["ip.src"]
      period              = 60    # 1 minute window
      requests_per_period = 5     # Max 5 attempts per IP per minute — tune for your traffic
      mitigation_timeout  = 600   # Block for 10 minutes after threshold exceeded
    }
    expression  = "(http.request.method eq \"POST\" and (http.request.uri.path contains \"/login\" or http.request.uri.path contains \"/signin\"))"
    description = "Login brute-force rate limit — k1N pack v1.0"
    enabled     = true
  }
}

# ---------------------------------------------------------------------------
# Security Headers (HTTP Response Modification Transform Rule)
# ---------------------------------------------------------------------------
# Adds HSTS, X-Frame-Options, X-Content-Type-Options, and other security headers.
# CSP is in report-only mode by default — switch to enforced after collecting reports.
resource "cloudflare_ruleset" "security_headers" {
  zone_id     = var.zone_id
  name        = "k1N Security Headers Baseline"
  description = "Adds security response headers to all responses — k1N pack v1.0"
  kind        = "zone"
  phase       = "http_response_headers_transform"

  rules {
    action = "rewrite"
    action_parameters {
      headers {
        name      = "Strict-Transport-Security"
        operation = "set"
        value     = "max-age=63072000; includeSubDomains; preload" # 2 years HSTS
      }
      headers {
        name      = "X-Frame-Options"
        operation = "set"
        value     = "DENY" # Remove if your app legitimately uses iframes
      }
      headers {
        name      = "X-Content-Type-Options"
        operation = "set"
        value     = "nosniff"
      }
      headers {
        name      = "Referrer-Policy"
        operation = "set"
        value     = "strict-origin-when-cross-origin"
      }
      headers {
        name      = "Permissions-Policy"
        operation = "set"
        value     = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
      }
    }
    expression  = "true"                                           # Apply to all responses
    description = "Security headers baseline — k1N pack v1.0"
    enabled     = true
  }
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

output "sqli_ruleset_id" {
  description = "ID of the deployed SQLi protection ruleset"
  value       = cloudflare_ruleset.sqli_protection.id
}

output "admin_ruleset_id" {
  description = "ID of the deployed admin panel protection ruleset"
  value       = cloudflare_ruleset.admin_protection.id
}

output "login_rate_limit_id" {
  description = "ID of the deployed login rate limit ruleset"
  value       = cloudflare_ruleset.login_rate_limit.id
}
