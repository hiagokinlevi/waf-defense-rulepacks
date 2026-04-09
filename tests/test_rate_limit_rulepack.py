"""
Tests for shared/rulepacks/rate_limit_rulepack.py

Validates:
  - RateLimitRule validation (invalid inputs raise ValueError)
  - Cloudflare, AWS WAF, and Azure WAF generator output structure
  - Per-IP and per-IP-per-path scope handling
  - HTTP method filter inclusion
  - Built-in rulepack factories produce valid, non-empty configs
  - RateLimitRulepack.summary() returns correct metadata
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.rulepacks.rate_limit_rulepack import (
    RateLimitAction,
    RateLimitRule,
    RateLimitRulepack,
    RateLimitScope,
    build_api_protection_pack,
    build_login_bruteforce_pack,
    generate_aws_waf,
    generate_azure_waf,
    generate_cloudflare,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rule(
    name: str = "Test rule",
    path: str = "/login",
    requests: int = 10,
    window: int = 60,
    scope: RateLimitScope = RateLimitScope.PER_IP,
    action: RateLimitAction = RateLimitAction.BLOCK,
    methods: list[str] | None = None,
) -> RateLimitRule:
    return RateLimitRule(
        name=name,
        path_pattern=path,
        requests=requests,
        window_seconds=window,
        scope=scope,
        action=action,
        http_methods=methods or [],
    )


# ---------------------------------------------------------------------------
# RateLimitRule validation
# ---------------------------------------------------------------------------

class TestRateLimitRuleValidation:

    def test_valid_rule_constructs(self):
        r = _rule()
        assert r.requests == 10
        assert r.window_seconds == 60

    def test_zero_requests_raises(self):
        with pytest.raises(ValueError):
            _rule(requests=0)

    def test_negative_requests_raises(self):
        with pytest.raises(ValueError):
            _rule(requests=-1)

    def test_window_too_small_raises(self):
        with pytest.raises(ValueError):
            _rule(window=5)

    def test_window_too_large_raises(self):
        with pytest.raises(ValueError):
            _rule(window=86401)

    def test_empty_name_raises(self):
        with pytest.raises(ValueError):
            _rule(name="")

    def test_empty_path_raises(self):
        with pytest.raises(ValueError):
            _rule(path="")

    def test_slug_alphanumeric(self):
        r = _rule(name="Login Brute-Force  Limit!")
        assert r.slug == "login_brute_force_limit"

    def test_requests_per_minute(self):
        r = _rule(requests=120, window=60)
        assert r.requests_per_minute == pytest.approx(120.0)


# ---------------------------------------------------------------------------
# Cloudflare generator
# ---------------------------------------------------------------------------

class TestGenerateCloudflare:

    def test_returns_dict(self):
        assert isinstance(generate_cloudflare(_rule()), dict)

    def test_threshold_matches_requests(self):
        r = _rule(requests=50)
        cf = generate_cloudflare(r)
        assert cf["threshold"] == 50

    def test_period_matches_window(self):
        r = _rule(window=120)
        cf = generate_cloudflare(r)
        assert cf["period"] == 120

    def test_block_action_maps_to_ban(self):
        cf = generate_cloudflare(_rule(action=RateLimitAction.BLOCK))
        assert cf["action"]["mode"] == "ban"

    def test_log_action_maps_to_simulate(self):
        cf = generate_cloudflare(_rule(action=RateLimitAction.LOG))
        assert cf["action"]["mode"] == "simulate"

    def test_challenge_action_maps_to_js_challenge(self):
        cf = generate_cloudflare(_rule(action=RateLimitAction.CHALLENGE))
        assert cf["action"]["mode"] == "js_challenge"

    def test_http_methods_included(self):
        r = _rule(methods=["POST", "PUT"])
        cf = generate_cloudflare(r)
        assert cf["match"]["request"]["methods"] == ["POST", "PUT"]

    def test_no_methods_no_method_key(self):
        r = _rule(methods=[])
        cf = generate_cloudflare(r)
        assert "methods" not in cf["match"]["request"]

    def test_disabled_rule_has_disabled_true(self):
        r = _rule()
        r2 = RateLimitRule(
            name=r.name, path_pattern=r.path_pattern,
            requests=r.requests, window_seconds=r.window_seconds,
            enabled=False,
        )
        cf = generate_cloudflare(r2)
        assert cf["disabled"] is True

    def test_per_ip_per_path_scope(self):
        r = _rule(scope=RateLimitScope.PER_IP_PER_PATH)
        cf = generate_cloudflare(r)
        assert cf["aggregate_key"]["type"] == "IP_with_NAT"

    def test_global_scope(self):
        r = _rule(scope=RateLimitScope.GLOBAL)
        cf = generate_cloudflare(r)
        assert cf["aggregate_key"]["type"] == "global"

    def test_meta_slug_present(self):
        r = _rule(name="My Test Rule")
        cf = generate_cloudflare(r)
        assert cf["_k1n_pack_meta"]["slug"] == "my_test_rule"


# ---------------------------------------------------------------------------
# AWS WAF generator
# ---------------------------------------------------------------------------

class TestGenerateAwsWaf:

    def test_returns_dict_with_name(self):
        r = _rule()
        aws = generate_aws_waf(r)
        assert isinstance(aws, dict)
        assert "Name" in aws

    def test_name_is_slug(self):
        r = _rule(name="Login Rate Limit")
        aws = generate_aws_waf(r)
        assert aws["Name"] == "login_rate_limit"

    def test_block_action(self):
        aws = generate_aws_waf(_rule(action=RateLimitAction.BLOCK))
        assert "BLOCK" in aws["Action"]

    def test_log_action_maps_to_count(self):
        aws = generate_aws_waf(_rule(action=RateLimitAction.LOG))
        assert "COUNT" in aws["Action"]

    def test_challenge_action_maps_to_captcha(self):
        aws = generate_aws_waf(_rule(action=RateLimitAction.CHALLENGE))
        assert "CAPTCHA" in aws["Action"]

    def test_aws_window_is_supported_value(self):
        """AWS WAF only supports 60, 120, 300, 600 second windows."""
        supported = {60, 120, 300, 600}
        r = _rule(window=90)  # 90 → rounds up to 120
        aws = generate_aws_waf(r)
        meta = aws["_k1n_pack_meta"]
        assert meta["aws_window"] in supported

    def test_aws_limit_minimum_100(self):
        """AWS WAF minimum rate limit is 100."""
        r = _rule(requests=5, window=60)  # very low → scaled minimum
        aws = generate_aws_waf(r)
        assert aws["_k1n_pack_meta"]["aws_limit"] >= 100

    def test_priority_present(self):
        r = RateLimitRule(
            name="p", path_pattern="/x", requests=10, window_seconds=60, priority=77
        )
        aws = generate_aws_waf(r)
        assert aws["Priority"] == 77

    def test_visibility_config_present(self):
        aws = generate_aws_waf(_rule())
        assert "VisibilityConfig" in aws


# ---------------------------------------------------------------------------
# Azure WAF generator
# ---------------------------------------------------------------------------

class TestGenerateAzureWaf:

    def test_returns_dict(self):
        assert isinstance(generate_azure_waf(_rule()), dict)

    def test_name_is_slug(self):
        r = _rule(name="My Azure Rule")
        az = generate_azure_waf(r)
        assert az["name"] == "my_azure_rule"

    def test_block_action(self):
        az = generate_azure_waf(_rule(action=RateLimitAction.BLOCK))
        assert az["action"] == "Block"

    def test_log_action(self):
        az = generate_azure_waf(_rule(action=RateLimitAction.LOG))
        assert az["action"] == "Log"

    def test_rate_limit_threshold_matches(self):
        r = _rule(requests=25)
        az = generate_azure_waf(r)
        assert az["rate_limit_threshold"] == 25

    def test_duration_at_least_1_minute(self):
        r = _rule(window=10)  # 10s → rounds to 1 minute minimum
        az = generate_azure_waf(r)
        assert az["rate_limit_duration_in_minutes"] >= 1

    def test_match_conditions_present(self):
        az = generate_azure_waf(_rule(path="/api/v1/*"))
        assert len(az["match_conditions"]) >= 1

    def test_http_methods_add_condition(self):
        r = _rule(methods=["POST"])
        az = generate_azure_waf(r)
        assert len(az["match_conditions"]) == 2  # path + method

    def test_enabled_flag(self):
        r = _rule()
        r2 = RateLimitRule(
            name=r.name, path_pattern=r.path_pattern,
            requests=r.requests, window_seconds=r.window_seconds,
            enabled=False,
        )
        az = generate_azure_waf(r2)
        assert az["enabled"] is False


# ---------------------------------------------------------------------------
# Built-in rulepack factories
# ---------------------------------------------------------------------------

class TestBuiltInRulepacks:

    def test_login_bruteforce_pack_has_rules(self):
        pack = build_login_bruteforce_pack()
        assert len(pack.rules) >= 2

    def test_api_protection_pack_has_rules(self):
        pack = build_api_protection_pack()
        assert len(pack.rules) >= 2

    def test_login_pack_summary_keys(self):
        pack = build_login_bruteforce_pack()
        summary = pack.summary()
        for key in ["name", "version", "description", "rule_count", "tags",
                    "scopes_used", "actions_used"]:
            assert key in summary

    def test_login_pack_all_rules_generate_valid_cloudflare(self):
        pack = build_login_bruteforce_pack()
        for rule in pack.rules:
            cf = generate_cloudflare(rule)
            assert cf["threshold"] >= 1
            assert cf["period"] >= 10

    def test_login_pack_all_rules_generate_valid_aws(self):
        pack = build_login_bruteforce_pack()
        for rule in pack.rules:
            aws = generate_aws_waf(rule)
            assert aws["Statement"]["RateBasedStatement"]["Limit"] >= 100

    def test_api_pack_all_rules_generate_valid_azure(self):
        pack = build_api_protection_pack()
        for rule in pack.rules:
            az = generate_azure_waf(rule)
            assert az["rate_limit_threshold"] >= 1

    def test_rulepack_add_returns_self(self):
        pack = RateLimitRulepack(name="test", version="1.0", description="test")
        result = pack.add(_rule())
        assert result is pack
