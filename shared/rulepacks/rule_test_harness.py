"""
WAF Rule Test Harness
======================
A lightweight test harness for evaluating WAF rule packs against sample
HTTP request fixtures. Simulates whether a given rule would match (and
what action it would take) for a set of test cases.

Design goals:
  - No external HTTP traffic — all evaluation is local against rule logic
  - Deterministic: same fixture → same result every run
  - Supports positive tests (malicious request → SHOULD match) and
    negative tests (benign request → SHOULD NOT match / false positive check)
  - Generates a structured test report with pass/fail per test case

Key classes:
  - HttpRequestFixture   : A synthetic HTTP request with method, path, headers, body
  - RuleTestCase         : A test case pairing a fixture with an expected outcome
  - RuleMatchResult      : The harness's evaluation of one test case
  - RuleTestSuite        : Collection of test cases with suite-level run() method
  - RuleTestReport       : Summary of a suite run (pass/fail counts, failures list)

Matching model:
  The harness evaluates rules from RateLimitRulepack (path pattern, method filter)
  and from WAF pack JSON files (via a simple keyword/regex matcher). It does NOT
  simulate full WAF semantics — it is a development-time sanity check, not a
  production WAF simulator.

Usage:
    from shared.rulepacks.rule_test_harness import (
        HttpRequestFixture,
        RuleTestCase,
        RuleTestSuite,
        MatchExpectation,
    )
    from shared.rulepacks.rate_limit_rulepack import (
        RateLimitRule, RateLimitScope, RateLimitAction
    )

    suite = RuleTestSuite(name="Login brute-force tests")
    suite.add_case(RuleTestCase(
        name="POST /login should match rate limit rule",
        fixture=HttpRequestFixture(method="POST", path="/login"),
        rule=login_rule,
        expectation=MatchExpectation.MATCH,
    ))
    report = suite.run()
    print(report.summary())
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional


# ---------------------------------------------------------------------------
# HTTP Request Fixture
# ---------------------------------------------------------------------------

@dataclass
class HttpRequestFixture:
    """
    A synthetic HTTP request used as a WAF rule test input.

    Attributes:
        method:         HTTP method (e.g., "GET", "POST").
        path:           URL path (e.g., "/login", "/api/v1/users").
        query_string:   URL query string (without leading '?').
        headers:        Dict of request headers.
        body:           Request body as a string (decoded).
        remote_ip:      Client IP address (used for rate-limit key simulation).
        description:    Optional human-readable description for test output.
    """
    method:       str                   = "GET"
    path:         str                   = "/"
    query_string: str                   = ""
    headers:      dict[str, str]        = field(default_factory=dict)
    body:         str                   = ""
    remote_ip:    str                   = "1.2.3.4"
    description:  str                   = ""

    @property
    def full_url(self) -> str:
        if self.query_string:
            return f"{self.path}?{self.query_string}"
        return self.path

    @property
    def user_agent(self) -> str:
        return self.headers.get("User-Agent", self.headers.get("user-agent", ""))

    @property
    def content_type(self) -> str:
        return self.headers.get("Content-Type", self.headers.get("content-type", ""))


# ---------------------------------------------------------------------------
# Match expectation and result
# ---------------------------------------------------------------------------

class MatchExpectation(str, Enum):
    MATCH    = "match"     # Rule SHOULD match (positive test — malicious request)
    NO_MATCH = "no_match"  # Rule should NOT match (negative test — benign request)


@dataclass
class RuleMatchResult:
    """
    Result of evaluating one test case against a rule.

    Attributes:
        test_case_name: Name of the test case.
        matched:        Whether the rule matched the fixture.
        expected:       The expected outcome (MATCH or NO_MATCH).
        passed:         True if matched == (expected == MATCH).
        match_reason:   Human-readable explanation of why the rule matched/didn't.
        action:         The action the rule would take (if matched), else None.
    """
    test_case_name: str
    matched:        bool
    expected:       MatchExpectation
    passed:         bool
    match_reason:   str                 = ""
    action:         Optional[str]       = None


# ---------------------------------------------------------------------------
# Rule test case
# ---------------------------------------------------------------------------

@dataclass
class RuleTestCase:
    """
    A single WAF rule test case.

    Attributes:
        name:        Human-readable test name.
        fixture:     The HTTP request fixture to evaluate.
        rule:        The rule object to test against. Must be a RateLimitRule or
                     a dict (WAF pack JSON) with a 'matcher' callable or patterns.
        expectation: Whether the rule should or should not match.
        tags:        Optional classification tags (e.g., ["sqli", "positive"]).
    """
    name:        str
    fixture:     HttpRequestFixture
    rule:        Any                          # RateLimitRule or dict pack
    expectation: MatchExpectation             = MatchExpectation.MATCH
    tags:        list[str]                    = field(default_factory=list)


# ---------------------------------------------------------------------------
# Matcher implementations
# ---------------------------------------------------------------------------

def _path_matches_pattern(path: str, pattern: str) -> bool:
    """
    Match a URL path against a glob pattern.

    Glob rules:
      ** → matches any path including slashes
      *  → matches one segment only (no slashes)

    A trailing slash on the path is tolerated (e.g., /login/ matches /login).
    """
    # Protect ** before processing single *
    regex = re.escape(pattern)
    regex = regex.replace(r"\*\*", "\x00DOUBLESTAR\x00")   # placeholder
    regex = regex.replace(r"\*", "[^/]*")                  # single segment
    regex = regex.replace("\x00DOUBLESTAR\x00", ".*")      # restore ** → .*
    return bool(re.match("^" + regex + r"/?$", path))


def _match_rate_limit_rule(fixture: HttpRequestFixture, rule: Any) -> tuple[bool, str]:
    """
    Check if a RateLimitRule matches a fixture (path + method filter).

    Returns (matched: bool, reason: str).
    """
    from shared.rulepacks.rate_limit_rulepack import RateLimitRule

    if not isinstance(rule, RateLimitRule):
        return False, "Rule is not a RateLimitRule"

    # Check path
    if not _path_matches_pattern(fixture.path, rule.path_pattern):
        return False, f"Path '{fixture.path}' does not match pattern '{rule.path_pattern}'"

    # Check HTTP method filter (if configured)
    if rule.http_methods:
        allowed_methods = [m.upper() for m in rule.http_methods]
        if fixture.method.upper() not in allowed_methods:
            return False, (
                f"Method '{fixture.method}' not in allowed {allowed_methods}"
            )

    # Check enabled
    if not rule.enabled:
        return False, "Rule is disabled"

    return True, f"Path matched '{rule.path_pattern}' and method matched"


def _match_pattern_rule(fixture: HttpRequestFixture, rule: dict) -> tuple[bool, str]:
    """
    Check if a pattern-based rule (WAF pack dict) matches a fixture.

    Looks for a 'test_patterns' key in the rule dict containing a list of
    regex patterns to match against the full request (method + path + query +
    headers + body combined into one string).

    Returns (matched: bool, reason: str).
    """
    patterns: list[str] = rule.get("test_patterns", [])
    if not patterns:
        return False, "Rule has no test_patterns for harness evaluation"

    # Build a searchable representation of the request
    request_repr = " ".join([
        fixture.method,
        fixture.full_url,
        fixture.body,
        " ".join(f"{k}: {v}" for k, v in fixture.headers.items()),
    ])

    for pattern in patterns:
        if re.search(pattern, request_repr, re.IGNORECASE):
            return True, f"Pattern '{pattern}' matched request representation"

    return False, f"No patterns matched request (checked {len(patterns)} patterns)"


def _evaluate_rule(fixture: HttpRequestFixture, rule: Any) -> tuple[bool, str, Optional[str]]:
    """
    Dispatch rule evaluation to the appropriate matcher.

    Returns (matched: bool, reason: str, action: Optional[str]).
    """
    # Import here to avoid circular imports in type hints
    try:
        from shared.rulepacks.rate_limit_rulepack import RateLimitRule
        if isinstance(rule, RateLimitRule):
            matched, reason = _match_rate_limit_rule(fixture, rule)
            action = rule.action.value if matched else None
            return matched, reason, action
    except ImportError:
        pass

    # Dict-based rule (WAF pack JSON with test_patterns)
    if isinstance(rule, dict):
        matched, reason = _match_pattern_rule(fixture, rule)
        action = rule.get("mode") if matched else None
        return matched, reason, action

    # Callable rule (custom matcher function)
    if callable(rule):
        matched = bool(rule(fixture))
        return matched, "Custom callable matcher", "custom" if matched else None

    return False, f"Unsupported rule type: {type(rule).__name__}", None


# ---------------------------------------------------------------------------
# Test suite
# ---------------------------------------------------------------------------

@dataclass
class RuleTestReport:
    """
    Summary of a RuleTestSuite run.

    Attributes:
        suite_name:   Name of the test suite.
        total:        Total test cases run.
        passed:       Count of passed test cases.
        failed:       Count of failed test cases.
        results:      All RuleMatchResult objects.
        failures:     Only the failed results.
    """
    suite_name:  str
    total:       int
    passed:      int
    failed:      int
    results:     list[RuleMatchResult]
    failures:    list[RuleMatchResult]

    @property
    def pass_rate(self) -> float:
        """Pass rate as a float in [0.0, 1.0]. 1.0 if no tests."""
        if self.total == 0:
            return 1.0
        return self.passed / self.total

    def summary(self) -> str:
        """Return a human-readable one-paragraph summary."""
        status = "PASS" if self.failed == 0 else "FAIL"
        lines = [
            f"=== {self.suite_name} [{status}] ===",
            f"Total: {self.total}  Passed: {self.passed}  Failed: {self.failed}"
            f"  ({self.pass_rate * 100:.0f}%)",
        ]
        if self.failures:
            lines.append("Failures:")
            for f in self.failures:
                exp = f.expected.value.upper()
                got = "MATCH" if f.matched else "NO_MATCH"
                lines.append(f"  FAIL [{f.test_case_name}]: expected {exp}, got {got} — {f.match_reason}")
        return "\n".join(lines)


class RuleTestSuite:
    """
    Collection of RuleTestCase objects with a run() method.

    Args:
        name: Suite name (used in report output).
    """

    def __init__(self, name: str) -> None:
        self.name  = name
        self._cases: list[RuleTestCase] = []

    def add_case(self, case: RuleTestCase) -> "RuleTestSuite":
        """Add a test case to the suite. Returns self for chaining."""
        self._cases.append(case)
        return self

    def add_positive(
        self,
        name: str,
        fixture: HttpRequestFixture,
        rule: Any,
        tags: Optional[list[str]] = None,
    ) -> "RuleTestSuite":
        """Shorthand: add a positive test (fixture SHOULD match the rule)."""
        return self.add_case(RuleTestCase(
            name=name,
            fixture=fixture,
            rule=rule,
            expectation=MatchExpectation.MATCH,
            tags=tags or [],
        ))

    def add_negative(
        self,
        name: str,
        fixture: HttpRequestFixture,
        rule: Any,
        tags: Optional[list[str]] = None,
    ) -> "RuleTestSuite":
        """Shorthand: add a negative test (fixture should NOT match the rule)."""
        return self.add_case(RuleTestCase(
            name=name,
            fixture=fixture,
            rule=rule,
            expectation=MatchExpectation.NO_MATCH,
            tags=tags or [],
        ))

    def run(self, tags: Optional[list[str]] = None) -> RuleTestReport:
        """
        Run all test cases (or a tagged subset) and return a RuleTestReport.

        Args:
            tags: If provided, only run test cases that have at least one of
                  these tags. If None/empty, run all cases.
        """
        cases_to_run = self._cases
        if tags:
            cases_to_run = [
                c for c in self._cases
                if any(t in c.tags for t in tags)
            ]

        results: list[RuleMatchResult] = []
        for case in cases_to_run:
            matched, reason, action = _evaluate_rule(case.fixture, case.rule)
            expected_match = case.expectation == MatchExpectation.MATCH
            passed = matched == expected_match

            results.append(RuleMatchResult(
                test_case_name=case.name,
                matched=matched,
                expected=case.expectation,
                passed=passed,
                match_reason=reason,
                action=action,
            ))

        failures = [r for r in results if not r.passed]
        return RuleTestReport(
            suite_name=self.name,
            total=len(results),
            passed=len(results) - len(failures),
            failed=len(failures),
            results=results,
            failures=failures,
        )

    def __len__(self) -> int:
        return len(self._cases)


# ---------------------------------------------------------------------------
# Convenience factory for common test fixture types
# ---------------------------------------------------------------------------

class Fixtures:
    """Factory for common attack and benign request fixtures."""

    @staticmethod
    def sqli_get(path: str = "/search") -> HttpRequestFixture:
        return HttpRequestFixture(
            method="GET",
            path=path,
            query_string="q=' OR 1=1--",
            description="Classic SQL injection in GET parameter",
        )

    @staticmethod
    def xss_get(path: str = "/search") -> HttpRequestFixture:
        return HttpRequestFixture(
            method="GET",
            path=path,
            query_string="q=<script>alert(1)</script>",
            description="Reflected XSS in GET parameter",
        )

    @staticmethod
    def lfi_get(path: str = "/download") -> HttpRequestFixture:
        return HttpRequestFixture(
            method="GET",
            path=path,
            query_string="file=../../../../etc/passwd",
            description="Path traversal / LFI attempt",
        )

    @staticmethod
    def login_post(path: str = "/login", ip: str = "1.2.3.4") -> HttpRequestFixture:
        return HttpRequestFixture(
            method="POST",
            path=path,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body="username=admin&password=password123",
            remote_ip=ip,
            description="Normal POST login request",
        )

    @staticmethod
    def benign_get(path: str = "/", ip: str = "1.2.3.4") -> HttpRequestFixture:
        return HttpRequestFixture(
            method="GET",
            path=path,
            headers={"User-Agent": "Mozilla/5.0"},
            remote_ip=ip,
            description="Benign browser GET request",
        )

    @staticmethod
    def api_get(path: str = "/api/v1/users", ip: str = "1.2.3.4") -> HttpRequestFixture:
        return HttpRequestFixture(
            method="GET",
            path=path,
            headers={
                "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
                "Accept": "application/json",
            },
            remote_ip=ip,
            description="Authenticated API GET request",
        )
