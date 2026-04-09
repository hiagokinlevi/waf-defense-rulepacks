"""
Per-IP / Per-Path Rate-Limiting Rulepack Generator
====================================================
Generates vendor-specific rate-limiting rule configurations for
Cloudflare, AWS WAF, and Azure WAF from a single declarative spec.

A RateLimitRule specifies:
  - path_pattern  : URL path glob (e.g., "/api/v1/*", "/login")
  - requests      : max requests per window
  - window_seconds: rolling window size in seconds
  - scope         : "per_ip" | "per_ip_per_path" | "global"
  - action        : "block" | "log" | "challenge"

From one rule spec, this module emits:
  - Cloudflare rate limit config (API / Terraform format)
  - AWS WAF rate-based rule statement
  - Azure WAF custom rule (rate limiting via match + count action)

Usage:
    from shared.rulepacks.rate_limit_rulepack import (
        RateLimitRule,
        RateLimitScope,
        RateLimitAction,
        RateLimitRulepack,
        generate_cloudflare,
        generate_aws_waf,
        generate_azure_waf,
    )

    rule = RateLimitRule(
        name="Login brute-force protection",
        path_pattern="/login",
        requests=10,
        window_seconds=60,
        scope=RateLimitScope.PER_IP,
        action=RateLimitAction.BLOCK,
    )

    cf_config   = generate_cloudflare(rule)
    aws_config  = generate_aws_waf(rule)
    azure_config = generate_azure_waf(rule)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class RateLimitScope(str, Enum):
    PER_IP           = "per_ip"
    PER_IP_PER_PATH  = "per_ip_per_path"
    GLOBAL           = "global"


class RateLimitAction(str, Enum):
    BLOCK     = "block"
    LOG       = "log"
    CHALLENGE = "challenge"


# ---------------------------------------------------------------------------
# Rule spec
# ---------------------------------------------------------------------------

@dataclass
class RateLimitRule:
    """
    Vendor-agnostic rate-limiting rule specification.

    Attributes:
        name:            Human-readable rule name (used as a label in generated configs).
        path_pattern:    URL path pattern. Supports simple globs: * = any segment,
                         ** = any path suffix. Exact paths also accepted.
        requests:        Maximum requests allowed in the window.
        window_seconds:  Rolling window duration in seconds (min 10, max 86400).
        scope:           Key used to bucket requests (per_ip / per_ip_per_path / global).
        action:          What to do when the limit is exceeded.
        description:     Optional description written into generated configs.
        http_methods:    Optional list of HTTP methods to match (empty = all methods).
        priority:        Rule priority (lower = higher priority in multi-rule stacks).
        enabled:         When False, rule is emitted in disabled/log-only state.
    """
    name:            str
    path_pattern:    str
    requests:        int
    window_seconds:  int
    scope:           RateLimitScope     = RateLimitScope.PER_IP
    action:          RateLimitAction    = RateLimitAction.BLOCK
    description:     str               = ""
    http_methods:    list[str]         = field(default_factory=list)
    priority:        int               = 100
    enabled:         bool              = True

    def __post_init__(self) -> None:
        if self.requests < 1:
            raise ValueError(f"requests must be >= 1, got {self.requests}")
        if not 10 <= self.window_seconds <= 86400:
            raise ValueError(
                f"window_seconds must be in [10, 86400], got {self.window_seconds}"
            )
        if not self.name.strip():
            raise ValueError("name must not be empty")
        if not self.path_pattern.strip():
            raise ValueError("path_pattern must not be empty")

    @property
    def slug(self) -> str:
        """Lowercase alphanumeric slug derived from the rule name."""
        return re.sub(r"[^a-z0-9]+", "_", self.name.lower()).strip("_")

    @property
    def requests_per_minute(self) -> float:
        """Normalized rate in requests/minute (informational only)."""
        return (self.requests / self.window_seconds) * 60.0


# ---------------------------------------------------------------------------
# Rulepack — collection of rules with metadata
# ---------------------------------------------------------------------------

@dataclass
class RateLimitRulepack:
    """
    A named collection of RateLimitRule objects with pack-level metadata.

    Attributes:
        name:        Pack identifier (e.g., "login-brute-force-baseline").
        version:     Semantic version string.
        description: Purpose of this rulepack.
        rules:       Ordered list of RateLimitRule objects.
        tags:        Optional list of classification tags.
    """
    name:        str
    version:     str
    description: str
    rules:       list[RateLimitRule] = field(default_factory=list)
    tags:        list[str]           = field(default_factory=list)

    def add(self, rule: RateLimitRule) -> "RateLimitRulepack":
        """Append a rule to the pack. Returns self for chaining."""
        self.rules.append(rule)
        return self

    def summary(self) -> dict[str, Any]:
        """Return a metadata summary dict (no vendor-specific content)."""
        return {
            "name":         self.name,
            "version":      self.version,
            "description":  self.description,
            "rule_count":   len(self.rules),
            "tags":         self.tags,
            "scopes_used":  sorted({r.scope.value for r in self.rules}),
            "actions_used": sorted({r.action.value for r in self.rules}),
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _glob_to_cloudflare_wildcard(pattern: str) -> str:
    """
    Convert a simple path glob to a Cloudflare URL match expression.

    Rules:
      /** at end → matches everything including nested paths
      /*  at end → matches one path segment
      No wildcard → exact prefix match
    """
    if pattern.endswith("/**"):
        return pattern[:-2] + "*"   # /api/** → /api/*
    if pattern.endswith("/*"):
        return pattern               # keep as-is, CF supports /*
    return pattern                   # exact path


def _path_to_aws_regex(pattern: str) -> str:
    """
    Convert a path glob to a Python/AWS WAF regex string.

    Wildcards:
      ** → .*   (any sequence including /)
      *  → [^/]* (one path segment, no slash)
    """
    regex = re.escape(pattern)
    # Un-escape wildcards we deliberately inserted
    regex = regex.replace(r"\*\*", ".*")
    regex = regex.replace(r"\*", "[^/]*")
    return "^" + regex + "($|/.*)"


def _cf_action(action: RateLimitAction) -> str:
    _map = {
        RateLimitAction.BLOCK:     "ban",
        RateLimitAction.LOG:       "simulate",
        RateLimitAction.CHALLENGE: "js_challenge",
    }
    return _map[action]


def _aws_action(action: RateLimitAction) -> str:
    _map = {
        RateLimitAction.BLOCK:     "BLOCK",
        RateLimitAction.LOG:       "COUNT",
        RateLimitAction.CHALLENGE: "CAPTCHA",
    }
    return _map[action]


def _azure_action(action: RateLimitAction) -> str:
    # Azure WAF custom rules support Block, Log, Allow, Redirect
    # CHALLENGE maps to Block (Azure does not have a native JS challenge in custom rules)
    _map = {
        RateLimitAction.BLOCK:     "Block",
        RateLimitAction.LOG:       "Log",
        RateLimitAction.CHALLENGE: "Block",
    }
    return _map[action]


def _cf_aggregate_key(scope: RateLimitScope) -> dict[str, Any]:
    if scope == RateLimitScope.PER_IP:
        return {"type": "IP"}
    elif scope == RateLimitScope.PER_IP_PER_PATH:
        return {"type": "IP_with_NAT", "group_by_headers": []}   # approximate
    else:  # GLOBAL
        return {"type": "global"}


def _aws_scope_key(scope: RateLimitScope) -> dict[str, Any]:
    if scope in (RateLimitScope.PER_IP, RateLimitScope.PER_IP_PER_PATH):
        return {
            "AggregateKeyType": "IP",
            "ScopeDownStatement": None,  # populated by caller if needed
        }
    return {"AggregateKeyType": "FORWARDED_IP"}


# ---------------------------------------------------------------------------
# Cloudflare generator
# ---------------------------------------------------------------------------

def generate_cloudflare(rule: RateLimitRule) -> dict[str, Any]:
    """
    Generate a Cloudflare rate limit config dict for the given rule.

    The output is compatible with the Cloudflare Rate Limiting API v1 format
    and the cloudflare_rate_limit Terraform resource.

    Args:
        rule: RateLimitRule spec.

    Returns:
        dict representing the Cloudflare rate limit rule.
    """
    url_pattern = _glob_to_cloudflare_wildcard(rule.path_pattern)

    config: dict[str, Any] = {
        "description": rule.description or rule.name,
        "disabled":    not rule.enabled,
        "match": {
            "request": {
                "url_pattern": f"*{url_pattern}",
            },
        },
        "threshold":   rule.requests,
        "period":      rule.window_seconds,
        "action": {
            "mode": _cf_action(rule.action),
            "timeout": rule.window_seconds * 2,
            "response": {
                "content_type": "application/json",
                "body": '{"error": "Rate limit exceeded. Please retry later."}',
            },
        },
        "aggregate_key": _cf_aggregate_key(rule.scope),
        # metadata
        "_k1n_pack_meta": {
            "rule_name":    rule.name,
            "slug":         rule.slug,
            "scope":        rule.scope.value,
            "action":       rule.action.value,
            "priority":     rule.priority,
            "req_per_min":  round(rule.requests_per_minute, 2),
        },
    }

    if rule.http_methods:
        config["match"]["request"]["methods"] = [m.upper() for m in rule.http_methods]

    return config


# ---------------------------------------------------------------------------
# AWS WAF generator
# ---------------------------------------------------------------------------

def generate_aws_waf(rule: RateLimitRule) -> dict[str, Any]:
    """
    Generate an AWS WAF v2 rate-based rule statement for the given rule.

    The output maps to the AWS::WAFv2::WebACL Rule type with a
    RateBasedStatement. Suitable for embedding in a CloudFormation template
    or Terraform aws_wafv2_web_acl resource.

    Args:
        rule: RateLimitRule spec.

    Returns:
        dict representing an AWS WAF rule object.
    """
    path_regex = _path_to_aws_regex(rule.path_pattern)

    # AWS WAF rate limit window must be 60, 120, 300, or 600 seconds.
    # Round up to the nearest supported window.
    aws_supported_windows = [60, 120, 300, 600]
    evaluation_window = next(
        (w for w in aws_supported_windows if w >= rule.window_seconds),
        600,
    )

    # AWS WAF limit is expressed as requests per evaluation window
    # Scale if our window differs from the requested one
    scaled_limit = max(
        100,  # AWS WAF minimum limit
        int(rule.requests * (evaluation_window / rule.window_seconds)),
    )

    scope_key = _aws_scope_key(rule.scope)

    rule_config: dict[str, Any] = {
        "Name":     rule.slug,
        "Priority": rule.priority,
        "Action": {
            _aws_action(rule.action): {}
        },
        "Statement": {
            "RateBasedStatement": {
                "Limit":             scaled_limit,
                "EvaluationWindowSec": evaluation_window,
                "AggregateKeyType":  scope_key["AggregateKeyType"],
                "ScopeDownStatement": {
                    "ByteMatchStatement": {
                        "SearchString":          rule.path_pattern.rstrip("/*"),
                        "FieldToMatch":          {"UriPath": {}},
                        "TextTransformations":   [{"Priority": 0, "Type": "URL_DECODE"}],
                        "PositionalConstraint":  "STARTS_WITH",
                    }
                },
            }
        },
        "VisibilityConfig": {
            "SampledRequestsEnabled":       True,
            "CloudWatchMetricsEnabled":     True,
            "MetricName":                   f"k1n_{rule.slug}",
        },
        # metadata
        "_k1n_pack_meta": {
            "rule_name":       rule.name,
            "original_window": rule.window_seconds,
            "aws_window":      evaluation_window,
            "original_limit":  rule.requests,
            "aws_limit":       scaled_limit,
            "scope":           rule.scope.value,
            "req_per_min":     round(rule.requests_per_minute, 2),
        },
    }

    if rule.http_methods:
        # Add HTTP method filter as an AND statement
        rule_config["Statement"]["RateBasedStatement"]["ScopeDownStatement"] = {
            "AndStatement": {
                "Statements": [
                    rule_config["Statement"]["RateBasedStatement"].pop("ScopeDownStatement"),
                    {
                        "ByteMatchStatement": {
                            "SearchString":        "|".join(m.upper() for m in rule.http_methods),
                            "FieldToMatch":        {"Method": {}},
                            "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                            "PositionalConstraint": "EXACTLY",
                        }
                    },
                ]
            }
        }

    return rule_config


# ---------------------------------------------------------------------------
# Azure WAF generator
# ---------------------------------------------------------------------------

def generate_azure_waf(rule: RateLimitRule) -> dict[str, Any]:
    """
    Generate an Azure WAF (Application Gateway WAF v2) custom rule dict for
    the given rule. Output conforms to the azurerm_web_application_firewall_policy
    custom_rules block structure.

    Note: Azure WAF custom rules use match conditions + override actions.
    True rate-limiting in Azure is achieved via Azure Front Door rate-limit
    rules or Application Gateway WAF + Azure Monitor alerts. This output
    represents the best-effort equivalent using custom match + action.

    Args:
        rule: RateLimitRule spec.

    Returns:
        dict representing an Azure WAF custom rule.
    """
    # Azure path match — strip trailing wildcard for CONTAINS match
    path_value = rule.path_pattern.rstrip("/*")
    if not path_value:
        path_value = "/"

    match_conditions: list[dict[str, Any]] = [
        {
            "match_variables": [{"variable_name": "RequestUri"}],
            "operator":        "Contains",
            "match_values":    [path_value],
            "negation_condition": False,
            "transforms":      ["UrlDecode", "Lowercase"],
        }
    ]

    if rule.http_methods:
        match_conditions.append({
            "match_variables": [{"variable_name": "RequestMethod"}],
            "operator":        "In",
            "match_values":    [m.upper() for m in rule.http_methods],
            "negation_condition": False,
            "transforms":      [],
        })

    return {
        "name":             rule.slug,
        "priority":         rule.priority,
        "rule_type":        "RateLimitRule",
        "action":           _azure_action(rule.action),
        "rate_limit_duration_in_minutes": max(1, rule.window_seconds // 60),
        "rate_limit_threshold":           rule.requests,
        "group_by_user_session": [{"group_by_variables": [{"variable_name": "SocketAddr"}]}],
        "match_conditions":  match_conditions,
        "enabled":           rule.enabled,
        # metadata
        "_k1n_pack_meta": {
            "rule_name":   rule.name,
            "scope":       rule.scope.value,
            "action":      rule.action.value,
            "priority":    rule.priority,
            "req_per_min": round(rule.requests_per_minute, 2),
        },
    }


# ---------------------------------------------------------------------------
# Built-in rulepacks
# ---------------------------------------------------------------------------

def build_login_bruteforce_pack() -> RateLimitRulepack:
    """
    Return the built-in login brute-force protection rulepack.

    Rules:
      1. Strict per-IP limit on POST /login  (10 req/60s — brute force block)
      2. Per-IP limit on all auth endpoints  (30 req/60s — credential stuffing)
      3. Global account recovery limiter     (5 req/300s — low-and-slow protection)
    """
    pack = RateLimitRulepack(
        name="login-brute-force-baseline",
        version="1.0.0",
        description=(
            "Per-IP rate limits for authentication endpoints. "
            "Blocks credential stuffing, brute force, and low-and-slow password spraying."
        ),
        tags=["auth", "brute-force", "credential-stuffing", "owasp-a07"],
    )
    pack.add(RateLimitRule(
        name="Login endpoint strict limit",
        path_pattern="/login",
        requests=10,
        window_seconds=60,
        scope=RateLimitScope.PER_IP,
        action=RateLimitAction.BLOCK,
        description="Block IPs exceeding 10 login attempts per minute",
        http_methods=["POST"],
        priority=10,
    ))
    pack.add(RateLimitRule(
        name="Auth path wide limit",
        path_pattern="/auth/*",
        requests=30,
        window_seconds=60,
        scope=RateLimitScope.PER_IP_PER_PATH,
        action=RateLimitAction.CHALLENGE,
        description="Challenge IPs exceeding 30 requests/min across all /auth/* paths",
        priority=20,
    ))
    pack.add(RateLimitRule(
        name="Account recovery low-and-slow limit",
        path_pattern="/forgot-password",
        requests=5,
        window_seconds=300,
        scope=RateLimitScope.PER_IP,
        action=RateLimitAction.BLOCK,
        description="Block IPs sending >5 password reset requests in 5 minutes",
        http_methods=["POST"],
        priority=30,
    ))
    return pack


def build_api_protection_pack() -> RateLimitRulepack:
    """
    Return the built-in API protection rulepack.

    Rules:
      1. General API rate limit  (200 req/60s per IP)
      2. Search endpoint limit   (20 req/60s per IP — prevents scraping)
      3. Export endpoint limit   (5 req/300s per IP — prevents bulk data theft)
    """
    pack = RateLimitRulepack(
        name="api-protection-baseline",
        version="1.0.0",
        description=(
            "Per-IP / per-path rate limits for REST API endpoints. "
            "Prevents API abuse, data scraping, and excessive resource consumption."
        ),
        tags=["api", "scraping", "resource-consumption", "owasp-api4"],
    )
    pack.add(RateLimitRule(
        name="API general rate limit",
        path_pattern="/api/**",
        requests=200,
        window_seconds=60,
        scope=RateLimitScope.PER_IP,
        action=RateLimitAction.BLOCK,
        description="Block IPs exceeding 200 API requests per minute",
        priority=50,
    ))
    pack.add(RateLimitRule(
        name="Search endpoint anti-scraping",
        path_pattern="/api/*/search",
        requests=20,
        window_seconds=60,
        scope=RateLimitScope.PER_IP_PER_PATH,
        action=RateLimitAction.CHALLENGE,
        description="Challenge rapid search requests that may indicate scraping",
        priority=40,
    ))
    pack.add(RateLimitRule(
        name="Export endpoint data-theft prevention",
        path_pattern="/api/*/export",
        requests=5,
        window_seconds=300,
        scope=RateLimitScope.PER_IP,
        action=RateLimitAction.BLOCK,
        description="Block IPs submitting >5 export requests in 5 minutes",
        priority=35,
    ))
    return pack
