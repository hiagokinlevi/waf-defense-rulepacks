"""
Tests for shared/rulepacks/rule_test_harness.py

Validates:
  - HttpRequestFixture field accessors
  - _path_matches_pattern() glob matching (internal, tested via public API)
  - RateLimitRule matching via harness (positive and negative cases)
  - MatchExpectation enum and RuleMatchResult pass/fail logic
  - RuleTestSuite.run() aggregation: pass/fail counts, summary()
  - RuleTestSuite tag filtering
  - Fixtures factory produces valid HttpRequestFixture objects
  - Dict-based pattern rules (test_patterns key)
  - RuleTestReport properties: pass_rate, summary()
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.rulepacks.rate_limit_rulepack import (
    RateLimitAction,
    RateLimitRule,
    RateLimitScope,
)
from shared.rulepacks.rule_test_harness import (
    Fixtures,
    HttpRequestFixture,
    MatchExpectation,
    RuleMatchResult,
    RuleTestCase,
    RuleTestReport,
    RuleTestSuite,
    _path_matches_pattern,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _login_rule(methods: list[str] | None = None) -> RateLimitRule:
    return RateLimitRule(
        name="Login rate limit",
        path_pattern="/login",
        requests=10,
        window_seconds=60,
        scope=RateLimitScope.PER_IP,
        action=RateLimitAction.BLOCK,
        http_methods=methods or [],
    )


def _api_rule() -> RateLimitRule:
    return RateLimitRule(
        name="API rate limit",
        path_pattern="/api/**",
        requests=100,
        window_seconds=60,
        scope=RateLimitScope.PER_IP,
        action=RateLimitAction.BLOCK,
    )


# ---------------------------------------------------------------------------
# _path_matches_pattern (internal helper)
# ---------------------------------------------------------------------------

class TestPathMatchesPattern:

    def test_exact_match(self):
        assert _path_matches_pattern("/login", "/login")

    def test_exact_no_match(self):
        assert not _path_matches_pattern("/logout", "/login")

    def test_single_wildcard_matches_segment(self):
        assert _path_matches_pattern("/api/v1", "/api/*")

    def test_single_wildcard_no_match_nested(self):
        # /api/* should NOT match /api/v1/users (two segments after /api/)
        assert not _path_matches_pattern("/api/v1/users", "/api/*")

    def test_double_wildcard_matches_nested(self):
        assert _path_matches_pattern("/api/v1/users", "/api/**")

    def test_double_wildcard_matches_deep_path(self):
        assert _path_matches_pattern("/api/v1/users/123/profile", "/api/**")

    def test_double_wildcard_matches_root(self):
        assert _path_matches_pattern("/api/v1", "/api/**")

    def test_trailing_slash_match(self):
        assert _path_matches_pattern("/login/", "/login")


# ---------------------------------------------------------------------------
# HttpRequestFixture
# ---------------------------------------------------------------------------

class TestHttpRequestFixture:

    def test_full_url_with_query(self):
        f = HttpRequestFixture(path="/search", query_string="q=test")
        assert f.full_url == "/search?q=test"

    def test_full_url_without_query(self):
        f = HttpRequestFixture(path="/search")
        assert f.full_url == "/search"

    def test_user_agent_from_headers(self):
        f = HttpRequestFixture(headers={"User-Agent": "TestBot/1.0"})
        assert f.user_agent == "TestBot/1.0"

    def test_user_agent_empty_when_absent(self):
        f = HttpRequestFixture()
        assert f.user_agent == ""

    def test_content_type_from_headers(self):
        f = HttpRequestFixture(headers={"Content-Type": "application/json"})
        assert f.content_type == "application/json"


# ---------------------------------------------------------------------------
# RuleTestSuite — RateLimitRule positive tests
# ---------------------------------------------------------------------------

class TestRuleTestSuitePositive:

    def test_login_post_matches_login_rule_with_method_filter(self):
        rule = _login_rule(methods=["POST"])
        fixture = HttpRequestFixture(method="POST", path="/login")
        suite = RuleTestSuite("test")
        suite.add_positive("POST /login matches", fixture, rule)
        report = suite.run()
        assert report.passed == 1
        assert report.failed == 0

    def test_login_get_does_not_match_post_only_rule(self):
        rule = _login_rule(methods=["POST"])
        fixture = HttpRequestFixture(method="GET", path="/login")
        suite = RuleTestSuite("test")
        suite.add_negative("GET /login no match for POST-only rule", fixture, rule)
        report = suite.run()
        assert report.passed == 1

    def test_api_path_matches_wildcard_rule(self):
        rule = _api_rule()
        fixture = HttpRequestFixture(method="GET", path="/api/v1/users")
        suite = RuleTestSuite("test")
        suite.add_positive("GET /api/v1/users matches /api/**", fixture, rule)
        report = suite.run()
        assert report.passed == 1

    def test_non_api_path_no_match(self):
        rule = _api_rule()
        fixture = HttpRequestFixture(method="GET", path="/login")
        suite = RuleTestSuite("test")
        suite.add_negative("/login no match for /api/**", fixture, rule)
        report = suite.run()
        assert report.passed == 1


# ---------------------------------------------------------------------------
# RuleTestSuite — pass/fail aggregation
# ---------------------------------------------------------------------------

class TestRuleTestSuiteAggregation:

    def test_all_pass_report(self):
        rule = _login_rule()
        suite = RuleTestSuite("all-pass")
        suite.add_positive("POST /login", HttpRequestFixture(method="POST", path="/login"), rule)
        suite.add_negative("GET /other", HttpRequestFixture(method="GET", path="/other"), rule)
        report = suite.run()
        assert report.total == 2
        assert report.passed == 2
        assert report.failed == 0

    def test_one_failure_report(self):
        rule = _login_rule(methods=["POST"])
        suite = RuleTestSuite("one-fail")
        # Wrong expectation — GET should not match POST-only rule, but we say MATCH
        suite.add_positive(
            "GET should match (wrong expectation)",
            HttpRequestFixture(method="GET", path="/login"),
            rule,
        )
        report = suite.run()
        assert report.failed == 1
        assert len(report.failures) == 1

    def test_empty_suite_report(self):
        suite = RuleTestSuite("empty")
        report = suite.run()
        assert report.total == 0
        assert report.passed == 0
        assert report.failed == 0
        assert report.pass_rate == 1.0

    def test_pass_rate_calculation(self):
        rule = _login_rule()
        suite = RuleTestSuite("pct")
        # 2 pass, 1 fail
        suite.add_positive("pass 1", HttpRequestFixture(path="/login"), rule)
        suite.add_positive("pass 2", HttpRequestFixture(path="/login"), rule)
        suite.add_positive(
            "fail (wrong expectation)",
            HttpRequestFixture(path="/other"),  # won't match
            rule,
        )
        report = suite.run()
        assert report.pass_rate == pytest.approx(2 / 3)

    def test_summary_contains_suite_name(self):
        suite = RuleTestSuite("my-suite-name")
        report = suite.run()
        assert "my-suite-name" in report.summary()

    def test_summary_contains_pass_when_all_pass(self):
        suite = RuleTestSuite("passing")
        rule = _login_rule()
        suite.add_positive("pass", HttpRequestFixture(path="/login"), rule)
        report = suite.run()
        assert "PASS" in report.summary()

    def test_summary_contains_fail_when_failures_exist(self):
        suite = RuleTestSuite("failing")
        rule = _login_rule(methods=["POST"])
        suite.add_positive(
            "should fail",
            HttpRequestFixture(method="GET", path="/login"),  # GET won't match
            rule,
        )
        report = suite.run()
        assert "FAIL" in report.summary()


# ---------------------------------------------------------------------------
# RuleTestSuite — tag filtering
# ---------------------------------------------------------------------------

class TestTagFiltering:

    def test_tag_filter_runs_only_matching_cases(self):
        rule = _login_rule()
        suite = RuleTestSuite("tags")
        suite.add_positive(
            "tagged sqli", HttpRequestFixture(path="/login"), rule,
            tags=["sqli"],
        )
        suite.add_positive(
            "tagged auth", HttpRequestFixture(path="/login"), rule,
            tags=["auth"],
        )
        # Only run 'sqli' tag
        report = suite.run(tags=["sqli"])
        assert report.total == 1

    def test_no_tag_filter_runs_all(self):
        rule = _login_rule()
        suite = RuleTestSuite("no-filter")
        for i in range(5):
            suite.add_positive(f"case {i}", HttpRequestFixture(path="/login"), rule)
        report = suite.run()
        assert report.total == 5

    def test_unmatched_tag_runs_nothing(self):
        rule = _login_rule()
        suite = RuleTestSuite("no-match")
        suite.add_positive("untagged", HttpRequestFixture(path="/login"), rule, tags=["auth"])
        report = suite.run(tags=["nonexistent_tag"])
        assert report.total == 0


# ---------------------------------------------------------------------------
# Dict-based pattern rules
# ---------------------------------------------------------------------------

class TestPatternBasedRules:

    def test_sqli_pattern_matches_sqli_fixture(self):
        rule = {"test_patterns": [r"OR\s+1=1", r"UNION\s+SELECT"], "mode": "block"}
        fixture = Fixtures.sqli_get("/search")
        suite = RuleTestSuite("pattern-test")
        suite.add_positive("SQLi pattern match", fixture, rule)
        report = suite.run()
        assert report.passed == 1

    def test_xss_pattern_matches_xss_fixture(self):
        rule = {"test_patterns": [r"<script>", r"javascript:"], "mode": "block"}
        fixture = Fixtures.xss_get("/search")
        suite = RuleTestSuite("xss-test")
        suite.add_positive("XSS pattern match", fixture, rule)
        report = suite.run()
        assert report.passed == 1

    def test_lfi_pattern_matches_lfi_fixture(self):
        rule = {"test_patterns": [r"\.\./", r"etc/passwd"], "mode": "block"}
        fixture = Fixtures.lfi_get()
        suite = RuleTestSuite("lfi-test")
        suite.add_positive("LFI pattern match", fixture, rule)
        report = suite.run()
        assert report.passed == 1

    def test_benign_request_no_pattern_match(self):
        rule = {"test_patterns": [r"OR\s+1=1"], "mode": "block"}
        fixture = Fixtures.benign_get("/")
        suite = RuleTestSuite("benign")
        suite.add_negative("Benign GET no match", fixture, rule)
        report = suite.run()
        assert report.passed == 1

    def test_rule_with_no_patterns_does_not_match(self):
        rule = {}  # No test_patterns key
        fixture = Fixtures.benign_get()
        suite = RuleTestSuite("no-patterns")
        suite.add_negative("No patterns no match", fixture, rule)
        report = suite.run()
        assert report.passed == 1


# ---------------------------------------------------------------------------
# Fixtures factory
# ---------------------------------------------------------------------------

class TestFixturesFactory:

    def test_sqli_fixture_has_sqli_payload(self):
        f = Fixtures.sqli_get()
        assert "OR" in f.query_string or "'" in f.query_string

    def test_xss_fixture_has_script_tag(self):
        f = Fixtures.xss_get()
        assert "script" in f.query_string.lower()

    def test_lfi_fixture_has_traversal(self):
        f = Fixtures.lfi_get()
        assert "../" in f.query_string or "etc" in f.query_string

    def test_login_post_fixture_method(self):
        f = Fixtures.login_post()
        assert f.method == "POST"
        assert "/login" in f.path

    def test_benign_get_fixture(self):
        f = Fixtures.benign_get("/about")
        assert f.method == "GET"
        assert f.path == "/about"

    def test_api_get_has_auth_header(self):
        f = Fixtures.api_get()
        assert "Authorization" in f.headers

    def test_len_of_suite(self):
        suite = RuleTestSuite("len-test")
        rule = _login_rule()
        suite.add_positive("c1", Fixtures.benign_get(), rule)
        suite.add_positive("c2", Fixtures.benign_get(), rule)
        assert len(suite) == 2


import pytest
