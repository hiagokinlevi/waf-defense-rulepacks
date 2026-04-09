"""
Tests for shared.rulepacks.rate_limit_policy
=============================================
Comprehensive pytest suite covering:
- RateLimitRule validation and serialization
- RateLimitPolicy accessors and serialization
- RateLimitPolicyGenerator.to_cloudflare()
- RateLimitPolicyGenerator.to_aws_waf()
- RateLimitPolicyGenerator.to_nginx()
- validate_all() error collection
- from_dict_list() round-trip deserialization
- Edge cases: disabled rules, multiple rules, all match keys, all actions
"""

from __future__ import annotations

import sys
import os
import math

import pytest

# ---------------------------------------------------------------------------
# Path bootstrap — allow running tests from repo root without install
# ---------------------------------------------------------------------------

# Insert the repo root (parent of 'shared') onto sys.path so imports resolve
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from shared.rulepacks.rate_limit_policy import (  # noqa: E402
    MatchKey,
    RateLimitPolicy,
    RateLimitPolicyGenerator,
    RateLimitRule,
    RuleAction,
)


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture()
def login_rule() -> RateLimitRule:
    """Standard login-endpoint rate limit rule used across multiple tests."""
    return RateLimitRule(
        rule_id="RL-LOGIN-001",
        name="Login endpoint rate limit",
        path_pattern="/api/v1/auth/login",
        threshold=10,
        window_seconds=60,
        action=RuleAction.BLOCK,
        match_key=MatchKey.IP,
    )


@pytest.fixture()
def api_rule() -> RateLimitRule:
    """Secondary API rule with a longer window and header-based match key."""
    return RateLimitRule(
        rule_id="RL-API-002",
        name="General API rate limit",
        path_pattern="/api/v1/",
        threshold=200,
        window_seconds=300,
        action=RuleAction.THROTTLE,
        match_key=MatchKey.HEADER,
        header_name="X-API-Key",
    )


@pytest.fixture()
def disabled_rule() -> RateLimitRule:
    """A rule with enabled=False, used to test filtering logic."""
    return RateLimitRule(
        rule_id="RL-DISABLED-003",
        name="Disabled rule",
        path_pattern="/legacy/endpoint",
        threshold=5,
        window_seconds=30,
        enabled=False,
    )


@pytest.fixture()
def generator() -> RateLimitPolicyGenerator:
    return RateLimitPolicyGenerator()


# ===========================================================================
# 1. MatchKey & RuleAction enums
# ===========================================================================

class TestEnums:
    def test_match_key_values(self):
        assert MatchKey.IP.value == "ip"
        assert MatchKey.HEADER.value == "header"
        assert MatchKey.COOKIE.value == "cookie"
        assert MatchKey.QUERY.value == "query"

    def test_rule_action_values(self):
        assert RuleAction.BLOCK.value == "block"
        assert RuleAction.CHALLENGE.value == "challenge"
        assert RuleAction.LOG.value == "log"
        assert RuleAction.THROTTLE.value == "throttle"

    def test_match_key_from_string(self):
        # Enum members are constructable from their .value strings
        assert MatchKey("ip") is MatchKey.IP
        assert MatchKey("header") is MatchKey.HEADER

    def test_rule_action_from_string(self):
        assert RuleAction("block") is RuleAction.BLOCK
        assert RuleAction("log") is RuleAction.LOG


# ===========================================================================
# 2. RateLimitRule — construction and defaults
# ===========================================================================

class TestRateLimitRuleDefaults:
    def test_default_action_is_block(self):
        rule = RateLimitRule("X", "X", "/x", 1, 1)
        assert rule.action == RuleAction.BLOCK

    def test_default_match_key_is_ip(self):
        rule = RateLimitRule("X", "X", "/x", 1, 1)
        assert rule.match_key == MatchKey.IP

    def test_default_enabled_is_true(self):
        rule = RateLimitRule("X", "X", "/x", 1, 1)
        assert rule.enabled is True

    def test_default_header_name_is_empty(self):
        rule = RateLimitRule("X", "X", "/x", 1, 1)
        assert rule.header_name == ""

    def test_default_tags_is_empty_list(self):
        rule = RateLimitRule("X", "X", "/x", 1, 1)
        assert rule.tags == []

    def test_tags_are_independent_between_instances(self):
        """Mutable default must not be shared across instances."""
        r1 = RateLimitRule("A", "A", "/a", 1, 1)
        r2 = RateLimitRule("B", "B", "/b", 1, 1)
        r1.tags.append("security")
        assert r2.tags == []


# ===========================================================================
# 3. RateLimitRule.validate()
# ===========================================================================

class TestRateLimitRuleValidate:
    def test_valid_rule_does_not_raise(self, login_rule):
        login_rule.validate()  # should not raise

    def test_zero_threshold_raises(self, login_rule):
        login_rule.threshold = 0
        with pytest.raises(ValueError, match="threshold"):
            login_rule.validate()

    def test_negative_threshold_raises(self, login_rule):
        login_rule.threshold = -5
        with pytest.raises(ValueError, match="threshold"):
            login_rule.validate()

    def test_zero_window_raises(self, login_rule):
        login_rule.window_seconds = 0
        with pytest.raises(ValueError, match="window_seconds"):
            login_rule.validate()

    def test_negative_window_raises(self, login_rule):
        login_rule.window_seconds = -10
        with pytest.raises(ValueError, match="window_seconds"):
            login_rule.validate()

    def test_empty_path_pattern_raises(self, login_rule):
        login_rule.path_pattern = ""
        with pytest.raises(ValueError, match="path_pattern"):
            login_rule.validate()

    def test_whitespace_only_path_pattern_raises(self, login_rule):
        login_rule.path_pattern = "   "
        with pytest.raises(ValueError, match="path_pattern"):
            login_rule.validate()

    def test_error_message_contains_rule_id(self, login_rule):
        login_rule.threshold = 0
        with pytest.raises(ValueError) as exc_info:
            login_rule.validate()
        assert login_rule.rule_id in str(exc_info.value)


# ===========================================================================
# 4. RateLimitRule.to_dict()
# ===========================================================================

class TestRateLimitRuleToDict:
    def test_to_dict_returns_dict(self, login_rule):
        assert isinstance(login_rule.to_dict(), dict)

    def test_to_dict_contains_all_keys(self, login_rule):
        d = login_rule.to_dict()
        expected_keys = {
            "rule_id", "name", "path_pattern", "threshold",
            "window_seconds", "action", "match_key", "header_name",
            "enabled", "tags",
        }
        assert expected_keys == set(d.keys())

    def test_action_serialized_as_string(self, login_rule):
        d = login_rule.to_dict()
        assert d["action"] == "block"
        assert isinstance(d["action"], str)

    def test_match_key_serialized_as_string(self, login_rule):
        d = login_rule.to_dict()
        assert d["match_key"] == "ip"
        assert isinstance(d["match_key"], str)

    def test_tags_serialized_as_list(self, login_rule):
        login_rule.tags = ["waf", "login"]
        d = login_rule.to_dict()
        assert d["tags"] == ["waf", "login"]

    def test_disabled_rule_serialized_correctly(self, disabled_rule):
        d = disabled_rule.to_dict()
        assert d["enabled"] is False


# ===========================================================================
# 5. RateLimitPolicy
# ===========================================================================

class TestRateLimitPolicy:
    def test_enabled_rules_excludes_disabled(self, login_rule, disabled_rule):
        policy = RateLimitPolicy(rules=[login_rule, disabled_rule])
        enabled = policy.enabled_rules
        assert login_rule in enabled
        assert disabled_rule not in enabled

    def test_enabled_rules_all_enabled(self, login_rule, api_rule):
        policy = RateLimitPolicy(rules=[login_rule, api_rule])
        assert len(policy.enabled_rules) == 2

    def test_enabled_rules_all_disabled(self, disabled_rule):
        policy = RateLimitPolicy(rules=[disabled_rule])
        assert policy.enabled_rules == []

    def test_rules_for_path_exact_match(self, login_rule):
        policy = RateLimitPolicy(rules=[login_rule])
        matches = policy.rules_for_path("/api/v1/auth/login")
        assert login_rule in matches

    def test_rules_for_path_prefix_match(self, api_rule):
        """path_pattern '/api/v1/' should match '/api/v1/users'."""
        policy = RateLimitPolicy(rules=[api_rule])
        matches = policy.rules_for_path("/api/v1/users")
        assert api_rule in matches

    def test_rules_for_path_no_match(self, login_rule):
        policy = RateLimitPolicy(rules=[login_rule])
        matches = policy.rules_for_path("/health")
        assert matches == []

    def test_rules_for_path_multiple_matches(self, login_rule, api_rule):
        """Both '/api/v1/' and '/api/v1/auth/login' should match the login path."""
        policy = RateLimitPolicy(rules=[login_rule, api_rule])
        matches = policy.rules_for_path("/api/v1/auth/login")
        assert login_rule in matches
        assert api_rule in matches

    def test_policy_default_name(self, login_rule):
        policy = RateLimitPolicy(rules=[login_rule])
        assert policy.policy_name == "default"

    def test_policy_to_dict_structure(self, login_rule, api_rule):
        policy = RateLimitPolicy(
            rules=[login_rule, api_rule],
            policy_name="prod-api",
            description="Production API policy",
        )
        d = policy.to_dict()
        assert d["policy_name"] == "prod-api"
        assert d["description"] == "Production API policy"
        assert "generated_at" in d
        assert isinstance(d["rules"], list)
        assert len(d["rules"]) == 2

    def test_policy_generated_at_is_float(self, login_rule):
        policy = RateLimitPolicy(rules=[login_rule])
        assert isinstance(policy.generated_at, float)


# ===========================================================================
# 6. RateLimitPolicyGenerator — to_cloudflare()
# ===========================================================================

class TestToCloudflare:
    def test_returns_list(self, generator, login_rule):
        result = generator.to_cloudflare([login_rule])
        assert isinstance(result, list)

    def test_one_rule_one_entry(self, generator, login_rule):
        result = generator.to_cloudflare([login_rule])
        assert len(result) == 1

    def test_multiple_rules_multiple_entries(self, generator, login_rule, api_rule):
        result = generator.to_cloudflare([login_rule, api_rule])
        assert len(result) == 2

    def test_required_keys_present(self, generator, login_rule):
        cf = generator.to_cloudflare([login_rule])[0]
        for key in ("id", "description", "match", "threshold", "period", "action", "enabled"):
            assert key in cf, f"Missing key: {key}"

    def test_id_equals_rule_id(self, generator, login_rule):
        cf = generator.to_cloudflare([login_rule])[0]
        assert cf["id"] == login_rule.rule_id

    def test_description_equals_name(self, generator, login_rule):
        cf = generator.to_cloudflare([login_rule])[0]
        assert cf["description"] == login_rule.name

    def test_threshold_value(self, generator, login_rule):
        cf = generator.to_cloudflare([login_rule])[0]
        assert cf["threshold"] == login_rule.threshold

    def test_period_equals_window_seconds(self, generator, login_rule):
        cf = generator.to_cloudflare([login_rule])[0]
        assert cf["period"] == login_rule.window_seconds

    def test_action_string(self, generator, login_rule):
        cf = generator.to_cloudflare([login_rule])[0]
        assert cf["action"] == "block"

    def test_enabled_flag(self, generator, disabled_rule):
        cf = generator.to_cloudflare([disabled_rule])[0]
        assert cf["enabled"] is False

    def test_match_structure_contains_path(self, generator, login_rule):
        cf = generator.to_cloudflare([login_rule])[0]
        path_val = cf["match"]["request"]["url"]["path"]["value"]
        assert path_val == login_rule.path_pattern

    def test_match_operator_is_contains(self, generator, login_rule):
        cf = generator.to_cloudflare([login_rule])[0]
        operator = cf["match"]["request"]["url"]["path"]["operator"]
        assert operator == "contains"

    def test_challenge_action(self, generator, login_rule):
        login_rule.action = RuleAction.CHALLENGE
        cf = generator.to_cloudflare([login_rule])[0]
        assert cf["action"] == "challenge"

    def test_empty_list_returns_empty_list(self, generator):
        assert generator.to_cloudflare([]) == []


# ===========================================================================
# 7. RateLimitPolicyGenerator — to_aws_waf()
# ===========================================================================

class TestToAwsWaf:
    def test_returns_list(self, generator, login_rule):
        result = generator.to_aws_waf([login_rule])
        assert isinstance(result, list)

    def test_one_rule_one_entry(self, generator, login_rule):
        assert len(generator.to_aws_waf([login_rule])) == 1

    def test_multiple_rules_multiple_entries(self, generator, login_rule, api_rule):
        assert len(generator.to_aws_waf([login_rule, api_rule])) == 2

    def test_required_top_level_keys(self, generator, login_rule):
        aws = generator.to_aws_waf([login_rule])[0]
        for key in ("Name", "Priority", "Statement", "Action", "VisibilityConfig"):
            assert key in aws, f"Missing key: {key}"

    def test_name_equals_rule_id(self, generator, login_rule):
        aws = generator.to_aws_waf([login_rule])[0]
        assert aws["Name"] == login_rule.rule_id

    def test_priority_starts_at_one(self, generator, login_rule):
        aws = generator.to_aws_waf([login_rule])[0]
        assert aws["Priority"] == 1

    def test_priority_increments_for_multiple_rules(self, generator, login_rule, api_rule):
        result = generator.to_aws_waf([login_rule, api_rule])
        assert result[0]["Priority"] == 1
        assert result[1]["Priority"] == 2

    def test_statement_has_rate_based_statement(self, generator, login_rule):
        aws = generator.to_aws_waf([login_rule])[0]
        assert "RateBasedStatement" in aws["Statement"]

    def test_rate_based_limit(self, generator, login_rule):
        rbs = generator.to_aws_waf([login_rule])[0]["Statement"]["RateBasedStatement"]
        assert rbs["Limit"] == login_rule.threshold

    def test_ip_match_key_produces_ip_aggregate(self, generator, login_rule):
        rbs = generator.to_aws_waf([login_rule])[0]["Statement"]["RateBasedStatement"]
        assert rbs["AggregateKeyType"] == "IP"

    def test_header_match_key_produces_forwarded_ip(self, generator, api_rule):
        """MatchKey.HEADER should produce FORWARDED_IP aggregate key."""
        rbs = generator.to_aws_waf([api_rule])[0]["Statement"]["RateBasedStatement"]
        assert rbs["AggregateKeyType"] == "FORWARDED_IP"

    def test_cookie_match_key_produces_forwarded_ip(self, generator, login_rule):
        login_rule.match_key = MatchKey.COOKIE
        rbs = generator.to_aws_waf([login_rule])[0]["Statement"]["RateBasedStatement"]
        assert rbs["AggregateKeyType"] == "FORWARDED_IP"

    def test_query_match_key_produces_forwarded_ip(self, generator, login_rule):
        login_rule.match_key = MatchKey.QUERY
        rbs = generator.to_aws_waf([login_rule])[0]["Statement"]["RateBasedStatement"]
        assert rbs["AggregateKeyType"] == "FORWARDED_IP"

    def test_scope_down_statement_contains_path(self, generator, login_rule):
        rbs = generator.to_aws_waf([login_rule])[0]["Statement"]["RateBasedStatement"]
        search_str = rbs["ScopeDownStatement"]["ByteMatchStatement"]["SearchString"]
        assert search_str == login_rule.path_pattern

    def test_scope_down_positional_constraint(self, generator, login_rule):
        rbs = generator.to_aws_waf([login_rule])[0]["Statement"]["RateBasedStatement"]
        constraint = rbs["ScopeDownStatement"]["ByteMatchStatement"]["PositionalConstraint"]
        assert constraint == "CONTAINS"

    def test_block_action_maps_to_block(self, generator, login_rule):
        aws = generator.to_aws_waf([login_rule])[0]
        assert aws["Action"] == {"Block": {}}

    def test_log_action_maps_to_count(self, generator, login_rule):
        login_rule.action = RuleAction.LOG
        aws = generator.to_aws_waf([login_rule])[0]
        assert aws["Action"] == {"Count": {}}

    def test_challenge_action_maps_to_count(self, generator, login_rule):
        login_rule.action = RuleAction.CHALLENGE
        aws = generator.to_aws_waf([login_rule])[0]
        assert aws["Action"] == {"Count": {}}

    def test_throttle_action_maps_to_count(self, generator, api_rule):
        """api_rule already uses THROTTLE action."""
        aws = generator.to_aws_waf([api_rule])[0]
        assert aws["Action"] == {"Count": {}}

    def test_visibility_config_keys(self, generator, login_rule):
        vc = generator.to_aws_waf([login_rule])[0]["VisibilityConfig"]
        assert vc["SampledRequestsEnabled"] is True
        assert vc["CloudWatchMetricsEnabled"] is True
        assert vc["MetricName"] == login_rule.rule_id

    def test_empty_list_returns_empty_list(self, generator):
        assert generator.to_aws_waf([]) == []


# ===========================================================================
# 8. RateLimitPolicyGenerator — to_nginx()
# ===========================================================================

class TestToNginx:
    def test_returns_string(self, generator, login_rule):
        result = generator.to_nginx([login_rule])
        assert isinstance(result, str)

    def test_zone_declaration_present(self, generator, login_rule):
        result = generator.to_nginx([login_rule])
        assert "limit_req_zone" in result

    def test_zone_name_uses_rule_id(self, generator, login_rule):
        result = generator.to_nginx([login_rule])
        assert f"{login_rule.rule_id}_zone" in result

    def test_location_block_present(self, generator, login_rule):
        result = generator.to_nginx([login_rule])
        assert f"location {login_rule.path_pattern}" in result

    def test_location_block_references_zone(self, generator, login_rule):
        result = generator.to_nginx([login_rule])
        assert f"limit_req zone={login_rule.rule_id}_zone" in result

    def test_limit_req_status_429(self, generator, login_rule):
        result = generator.to_nginx([login_rule])
        assert "limit_req_status 429" in result

    def test_rate_unit_is_r_per_minute_when_window_lte_60(self, generator, login_rule):
        """window_seconds=60 → rate expressed as r/m."""
        result = generator.to_nginx([login_rule])
        assert "r/m" in result

    def test_rate_value_for_per_minute_window(self, generator, login_rule):
        """threshold=10, window=60 → rate=10r/m."""
        result = generator.to_nginx([login_rule])
        assert "rate=10r/m" in result

    def test_rate_unit_is_r_per_second_when_window_gt_60(self, generator, api_rule):
        """window_seconds=300 → rate expressed as r/s."""
        result = generator.to_nginx([api_rule])
        assert "r/s" in result

    def test_rate_value_for_per_second_window(self, generator, api_rule):
        """threshold=200, window=300 → rps=200//300=0 → clamped to 1r/s."""
        result = generator.to_nginx([api_rule])
        assert "rate=1r/s" in result

    def test_rate_per_second_calculation_above_one(self, generator, login_rule):
        """threshold=600, window=120 → rps=5r/s."""
        login_rule.threshold = 600
        login_rule.window_seconds = 120
        result = generator.to_nginx([login_rule])
        assert "rate=5r/s" in result

    def test_burst_is_threshold_over_five(self, generator, login_rule):
        """threshold=10 → burst=max(1, 10//5)=2."""
        result = generator.to_nginx([login_rule])
        assert "burst=2" in result

    def test_burst_minimum_is_one(self, generator, login_rule):
        """threshold=3 → 3//5=0 → burst=1."""
        login_rule.threshold = 3
        result = generator.to_nginx([login_rule])
        assert "burst=1" in result

    def test_nodelay_present(self, generator, login_rule):
        result = generator.to_nginx([login_rule])
        assert "nodelay" in result

    def test_multiple_rules_produce_multiple_zones(self, generator, login_rule, api_rule):
        result = generator.to_nginx([login_rule, api_rule])
        assert result.count("limit_req_zone") == 2

    def test_multiple_rules_produce_multiple_locations(self, generator, login_rule, api_rule):
        result = generator.to_nginx([login_rule, api_rule])
        assert result.count("location /") == 2

    def test_empty_list_returns_string_with_headers(self, generator):
        """Even with no rules the output should be a non-empty string (headers)."""
        result = generator.to_nginx([])
        assert isinstance(result, str)
        assert len(result) > 0


# ===========================================================================
# 9. validate_all()
# ===========================================================================

class TestValidateAll:
    def test_all_valid_returns_empty_list(self, generator, login_rule, api_rule):
        errors = generator.validate_all([login_rule, api_rule])
        assert errors == []

    def test_single_invalid_rule_returns_one_error(self, generator, login_rule):
        login_rule.threshold = 0
        errors = generator.validate_all([login_rule])
        assert len(errors) == 1

    def test_multiple_invalid_rules_returns_multiple_errors(self, generator, login_rule, api_rule):
        login_rule.threshold = -1
        api_rule.window_seconds = 0
        errors = generator.validate_all([login_rule, api_rule])
        assert len(errors) == 2

    def test_error_message_is_string(self, generator, login_rule):
        login_rule.threshold = 0
        errors = generator.validate_all([login_rule])
        assert isinstance(errors[0], str)

    def test_mixed_valid_invalid(self, generator, login_rule, api_rule, disabled_rule):
        login_rule.threshold = 0          # invalid
        # api_rule and disabled_rule are valid
        errors = generator.validate_all([login_rule, api_rule, disabled_rule])
        assert len(errors) == 1


# ===========================================================================
# 10. from_dict_list() — deserialization & round-trip
# ===========================================================================

class TestFromDictList:
    def test_round_trip_single_rule(self, generator, login_rule):
        serialized = [login_rule.to_dict()]
        restored = generator.from_dict_list(serialized)
        assert len(restored) == 1
        r = restored[0]
        assert r.rule_id == login_rule.rule_id
        assert r.name == login_rule.name
        assert r.path_pattern == login_rule.path_pattern
        assert r.threshold == login_rule.threshold
        assert r.window_seconds == login_rule.window_seconds

    def test_round_trip_action_enum(self, generator, login_rule):
        restored = generator.from_dict_list([login_rule.to_dict()])
        assert restored[0].action == RuleAction.BLOCK

    def test_round_trip_match_key_enum(self, generator, login_rule):
        restored = generator.from_dict_list([login_rule.to_dict()])
        assert restored[0].match_key == MatchKey.IP

    def test_round_trip_header_match_key(self, generator, api_rule):
        restored = generator.from_dict_list([api_rule.to_dict()])
        assert restored[0].match_key == MatchKey.HEADER
        assert restored[0].header_name == api_rule.header_name

    def test_round_trip_disabled_flag(self, generator, disabled_rule):
        restored = generator.from_dict_list([disabled_rule.to_dict()])
        assert restored[0].enabled is False

    def test_round_trip_tags(self, generator, login_rule):
        login_rule.tags = ["auth", "critical"]
        restored = generator.from_dict_list([login_rule.to_dict()])
        assert restored[0].tags == ["auth", "critical"]

    def test_round_trip_multiple_rules(self, generator, login_rule, api_rule):
        data = [login_rule.to_dict(), api_rule.to_dict()]
        restored = generator.from_dict_list(data)
        assert len(restored) == 2
        assert restored[0].rule_id == login_rule.rule_id
        assert restored[1].rule_id == api_rule.rule_id

    def test_empty_list_returns_empty_list(self, generator):
        assert generator.from_dict_list([]) == []

    def test_restored_rules_pass_validation(self, generator, login_rule, api_rule):
        data = [login_rule.to_dict(), api_rule.to_dict()]
        restored = generator.from_dict_list(data)
        errors = generator.validate_all(restored)
        assert errors == []
