#!/usr/bin/env python3
"""
Tests for shared/rulepacks/header_security_pack.py
====================================================
Covers all 10 checks (HDR-001 through HDR-010), report structure,
case-insensitive header matching, happy paths, boundary conditions,
batch evaluation, optional-flag behaviour, and risk score capping.

Run with:
    python -m pytest tests/test_header_security_pack.py -v

Or from the repo root:
    python -m pytest -v
"""

from __future__ import annotations

import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup — makes the import work regardless of how pytest is invoked.
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "shared" / "rulepacks"))

import pytest
from header_security_pack import (
    HeaderMatch,
    HeaderResult,
    HeaderSecurityPack,
    HeaderSeverity,
    _RULE_WEIGHTS,
)


# ---------------------------------------------------------------------------
# Helper: a fully-hardened header dict (all checks should pass silently)
# ---------------------------------------------------------------------------

def _clean_headers() -> dict:
    """
    Return a header dict with every security control correctly configured.
    A default-configured HeaderSecurityPack.evaluate() run against these
    headers must produce zero findings.
    """
    return {
        "Content-Type": "text/html; charset=utf-8",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'; script-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        # No Server header; no X-Powered-By header.
    }


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture()
def pack() -> HeaderSecurityPack:
    """Default pack instance (all checks active, min_hsts_age=31536000)."""
    return HeaderSecurityPack()


# ===========================================================================
# Section 1 – HDR-001: Missing Strict-Transport-Security
# ===========================================================================

class TestHdr001:
    """HDR-001 fires when HSTS header is absent."""

    def test_fires_when_hsts_missing(self, pack):
        headers = {"Content-Type": "text/html"}
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-001" in rule_ids

    def test_does_not_fire_when_hsts_present(self, pack):
        headers = _clean_headers()
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-001" not in rule_ids

    def test_severity_is_high(self, pack):
        result = pack.evaluate({"Content-Type": "text/html"})
        match = next(m for m in result.matches if m.rule_id == "HDR-001")
        assert match.severity == HeaderSeverity.HIGH

    def test_remediation_is_populated(self, pack):
        result = pack.evaluate({"Content-Type": "text/html"})
        match = next(m for m in result.matches if m.rule_id == "HDR-001")
        assert match.remediation != ""

    def test_require_hsts_false_skips_check(self):
        pack = HeaderSecurityPack(require_hsts=False)
        result = pack.evaluate({"Content-Type": "text/html"})
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-001" not in rule_ids

    def test_case_insensitive_key(self, pack):
        # Header name in ALL CAPS should still be detected as present.
        headers = dict(_clean_headers())
        # Replace the normally-cased key with uppercase.
        del headers["Strict-Transport-Security"]
        headers["STRICT-TRANSPORT-SECURITY"] = "max-age=31536000; includeSubDomains"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-001" not in rule_ids


# ===========================================================================
# Section 2 – HDR-002: HSTS max-age too short
# ===========================================================================

class TestHdr002:
    """HDR-002 fires when HSTS is present but max-age < min_hsts_age."""

    MIN_AGE = 31536000  # one year in seconds

    def test_fires_when_max_age_below_minimum(self, pack):
        headers = _clean_headers()
        headers["Strict-Transport-Security"] = f"max-age={self.MIN_AGE - 1}"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-002" in rule_ids

    def test_does_not_fire_when_max_age_exactly_minimum(self, pack):
        headers = _clean_headers()
        headers["Strict-Transport-Security"] = f"max-age={self.MIN_AGE}"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-002" not in rule_ids

    def test_does_not_fire_when_max_age_above_minimum(self, pack):
        headers = _clean_headers()
        headers["Strict-Transport-Security"] = f"max-age={self.MIN_AGE + 1}"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-002" not in rule_ids

    def test_boundary_one_less_than_minimum(self, pack):
        # Exactly one second below minimum must fire.
        headers = _clean_headers()
        headers["Strict-Transport-Security"] = f"max-age={self.MIN_AGE - 1}"
        result = pack.evaluate(headers)
        assert any(m.rule_id == "HDR-002" for m in result.matches)

    def test_fires_when_max_age_very_small(self, pack):
        headers = _clean_headers()
        headers["Strict-Transport-Security"] = "max-age=3600"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-002" in rule_ids

    def test_fires_when_max_age_unparseable(self, pack):
        # A malformed HSTS value without a parseable max-age should fire.
        headers = _clean_headers()
        headers["Strict-Transport-Security"] = "includeSubDomains"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-002" in rule_ids

    def test_custom_min_hsts_age(self):
        # A pack with a shorter min_hsts_age should accept correspondingly
        # shorter max-age values.
        pack = HeaderSecurityPack(min_hsts_age=86400)  # 1 day
        headers = _clean_headers()
        headers["Strict-Transport-Security"] = "max-age=86400"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-002" not in rule_ids

    def test_severity_is_medium(self, pack):
        headers = _clean_headers()
        headers["Strict-Transport-Security"] = "max-age=1000"
        result = pack.evaluate(headers)
        match = next(m for m in result.matches if m.rule_id == "HDR-002")
        assert match.severity == HeaderSeverity.MEDIUM

    def test_evidence_contains_header_value(self, pack):
        hsts_val = "max-age=3600"
        headers = _clean_headers()
        headers["Strict-Transport-Security"] = hsts_val
        result = pack.evaluate(headers)
        match = next(m for m in result.matches if m.rule_id == "HDR-002")
        assert hsts_val in match.evidence

    def test_does_not_fire_when_hsts_missing(self, pack):
        # If HSTS itself is missing, HDR-001 fires but not HDR-002.
        headers = {"Content-Type": "text/html"}
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-002" not in rule_ids


# ===========================================================================
# Section 3 – HDR-003: Missing Content-Security-Policy
# ===========================================================================

class TestHdr003:
    """HDR-003 fires when CSP header is absent and require_csp=True."""

    def test_fires_when_csp_missing(self, pack):
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-003" in rule_ids

    def test_does_not_fire_when_csp_present(self, pack):
        result = pack.evaluate(_clean_headers())
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-003" not in rule_ids

    def test_require_csp_false_skips_check(self):
        pack = HeaderSecurityPack(require_csp=False)
        headers = {"Content-Type": "text/html"}
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-003" not in rule_ids

    def test_severity_is_high(self, pack):
        headers = dict(_clean_headers())
        del headers["Content-Security-Policy"]
        result = pack.evaluate(headers)
        match = next(m for m in result.matches if m.rule_id == "HDR-003")
        assert match.severity == HeaderSeverity.HIGH

    def test_case_insensitive_csp_key(self, pack):
        headers = dict(_clean_headers())
        del headers["Content-Security-Policy"]
        headers["CONTENT-SECURITY-POLICY"] = "default-src 'self'"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-003" not in rule_ids


# ===========================================================================
# Section 4 – HDR-004: Missing X-Frame-Options
# ===========================================================================

class TestHdr004:
    """HDR-004 fires when X-Frame-Options is absent."""

    def test_fires_when_xfo_missing(self, pack):
        headers = dict(_clean_headers())
        del headers["X-Frame-Options"]
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-004" in rule_ids

    def test_does_not_fire_when_xfo_deny(self, pack):
        result = pack.evaluate(_clean_headers())
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-004" not in rule_ids

    def test_does_not_fire_when_xfo_sameorigin(self, pack):
        headers = dict(_clean_headers())
        headers["X-Frame-Options"] = "SAMEORIGIN"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-004" not in rule_ids

    def test_severity_is_medium(self, pack):
        headers = dict(_clean_headers())
        del headers["X-Frame-Options"]
        result = pack.evaluate(headers)
        match = next(m for m in result.matches if m.rule_id == "HDR-004")
        assert match.severity == HeaderSeverity.MEDIUM

    def test_case_insensitive_key(self, pack):
        headers = dict(_clean_headers())
        del headers["X-Frame-Options"]
        headers["x-frame-options"] = "DENY"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-004" not in rule_ids


# ===========================================================================
# Section 5 – HDR-005: Missing or wrong X-Content-Type-Options
# ===========================================================================

class TestHdr005:
    """HDR-005 fires when X-Content-Type-Options is absent or != 'nosniff'."""

    def test_fires_when_header_missing(self, pack):
        headers = dict(_clean_headers())
        del headers["X-Content-Type-Options"]
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-005" in rule_ids

    def test_fires_when_value_not_nosniff(self, pack):
        headers = dict(_clean_headers())
        headers["X-Content-Type-Options"] = "sniff"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-005" in rule_ids

    def test_does_not_fire_when_nosniff_lowercase(self, pack):
        headers = dict(_clean_headers())
        headers["X-Content-Type-Options"] = "nosniff"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-005" not in rule_ids

    def test_does_not_fire_when_nosniff_uppercase(self, pack):
        # Value matching should be case-insensitive.
        headers = dict(_clean_headers())
        headers["X-Content-Type-Options"] = "NOSNIFF"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-005" not in rule_ids

    def test_does_not_fire_when_nosniff_mixed_case(self, pack):
        headers = dict(_clean_headers())
        headers["X-Content-Type-Options"] = "NoSniff"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-005" not in rule_ids

    def test_severity_is_medium(self, pack):
        headers = dict(_clean_headers())
        del headers["X-Content-Type-Options"]
        result = pack.evaluate(headers)
        match = next(m for m in result.matches if m.rule_id == "HDR-005")
        assert match.severity == HeaderSeverity.MEDIUM

    def test_case_insensitive_header_key(self, pack):
        headers = dict(_clean_headers())
        del headers["X-Content-Type-Options"]
        headers["X-CONTENT-TYPE-OPTIONS"] = "nosniff"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-005" not in rule_ids


# ===========================================================================
# Section 6 – HDR-006: Missing Referrer-Policy
# ===========================================================================

class TestHdr006:
    """HDR-006 fires when Referrer-Policy is absent."""

    def test_fires_when_referrer_policy_missing(self, pack):
        headers = dict(_clean_headers())
        del headers["Referrer-Policy"]
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-006" in rule_ids

    def test_does_not_fire_when_present(self, pack):
        result = pack.evaluate(_clean_headers())
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-006" not in rule_ids

    def test_severity_is_low(self, pack):
        headers = dict(_clean_headers())
        del headers["Referrer-Policy"]
        result = pack.evaluate(headers)
        match = next(m for m in result.matches if m.rule_id == "HDR-006")
        assert match.severity == HeaderSeverity.LOW

    def test_case_insensitive_header_key(self, pack):
        headers = dict(_clean_headers())
        del headers["Referrer-Policy"]
        headers["REFERRER-POLICY"] = "no-referrer"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-006" not in rule_ids


# ===========================================================================
# Section 7 – HDR-007: Server header leaks version information
# ===========================================================================

class TestHdr007:
    """HDR-007 fires when the Server header contains version digits."""

    def test_fires_on_apache_version(self, pack):
        headers = dict(_clean_headers())
        headers["Server"] = "Apache/2.4.52 (Ubuntu)"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-007" in rule_ids

    def test_fires_on_nginx_version(self, pack):
        headers = dict(_clean_headers())
        headers["Server"] = "nginx/1.22.0"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-007" in rule_ids

    def test_fires_on_iis_version(self, pack):
        headers = dict(_clean_headers())
        headers["Server"] = "Microsoft-IIS/10.0"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-007" in rule_ids

    def test_fires_on_generic_version_string(self, pack):
        headers = dict(_clean_headers())
        headers["Server"] = "CustomServer/3.5.1"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-007" in rule_ids

    def test_does_not_fire_when_server_absent(self, pack):
        # _clean_headers() intentionally omits the Server header.
        result = pack.evaluate(_clean_headers())
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-007" not in rule_ids

    def test_does_not_fire_on_generic_server_token(self, pack):
        # A bare token with no digits should be considered safe.
        headers = dict(_clean_headers())
        headers["Server"] = "web"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-007" not in rule_ids

    def test_severity_is_medium(self, pack):
        headers = dict(_clean_headers())
        headers["Server"] = "Apache/2.4.52"
        result = pack.evaluate(headers)
        match = next(m for m in result.matches if m.rule_id == "HDR-007")
        assert match.severity == HeaderSeverity.MEDIUM

    def test_evidence_contains_server_value(self, pack):
        server_val = "Apache/2.4.52 (Ubuntu)"
        headers = dict(_clean_headers())
        headers["Server"] = server_val
        result = pack.evaluate(headers)
        match = next(m for m in result.matches if m.rule_id == "HDR-007")
        assert server_val in match.evidence

    def test_case_insensitive_server_key(self, pack):
        headers = dict(_clean_headers())
        headers["SERVER"] = "Apache/2.4.52"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-007" in rule_ids


# ===========================================================================
# Section 8 – HDR-008: X-Powered-By header present
# ===========================================================================

class TestHdr008:
    """HDR-008 fires whenever X-Powered-By is present."""

    def test_fires_on_php_disclosure(self, pack):
        headers = dict(_clean_headers())
        headers["X-Powered-By"] = "PHP/8.1.0"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-008" in rule_ids

    def test_fires_on_aspnet_disclosure(self, pack):
        headers = dict(_clean_headers())
        headers["X-Powered-By"] = "ASP.NET"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-008" in rule_ids

    def test_does_not_fire_when_absent(self, pack):
        result = pack.evaluate(_clean_headers())
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-008" not in rule_ids

    def test_severity_is_low(self, pack):
        headers = dict(_clean_headers())
        headers["X-Powered-By"] = "PHP/8.1.0"
        result = pack.evaluate(headers)
        match = next(m for m in result.matches if m.rule_id == "HDR-008")
        assert match.severity == HeaderSeverity.LOW

    def test_evidence_contains_header_value(self, pack):
        xpb_val = "PHP/8.1.0"
        headers = dict(_clean_headers())
        headers["X-Powered-By"] = xpb_val
        result = pack.evaluate(headers)
        match = next(m for m in result.matches if m.rule_id == "HDR-008")
        assert xpb_val in match.evidence

    def test_case_insensitive_key(self, pack):
        headers = dict(_clean_headers())
        headers["x-powered-by"] = "Express"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-008" in rule_ids


# ===========================================================================
# Section 9 – HDR-009: Missing Permissions-Policy
# ===========================================================================

class TestHdr009:
    """HDR-009 fires when neither Permissions-Policy nor Feature-Policy is present."""

    def test_fires_when_both_absent(self, pack):
        headers = dict(_clean_headers())
        del headers["Permissions-Policy"]
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-009" in rule_ids

    def test_does_not_fire_when_permissions_policy_present(self, pack):
        result = pack.evaluate(_clean_headers())
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-009" not in rule_ids

    def test_does_not_fire_when_feature_policy_present(self, pack):
        # Legacy Feature-Policy header should be accepted as sufficient.
        headers = dict(_clean_headers())
        del headers["Permissions-Policy"]
        headers["Feature-Policy"] = "geolocation 'none'"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-009" not in rule_ids

    def test_require_permissions_policy_false_skips_check(self):
        pack = HeaderSecurityPack(require_permissions_policy=False)
        headers = {"Content-Type": "text/html"}
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-009" not in rule_ids

    def test_severity_is_low(self, pack):
        headers = dict(_clean_headers())
        del headers["Permissions-Policy"]
        result = pack.evaluate(headers)
        match = next(m for m in result.matches if m.rule_id == "HDR-009")
        assert match.severity == HeaderSeverity.LOW

    def test_case_insensitive_permissions_policy_key(self, pack):
        headers = dict(_clean_headers())
        del headers["Permissions-Policy"]
        headers["PERMISSIONS-POLICY"] = "geolocation=()"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-009" not in rule_ids

    def test_case_insensitive_feature_policy_key(self, pack):
        headers = dict(_clean_headers())
        del headers["Permissions-Policy"]
        headers["FEATURE-POLICY"] = "geolocation 'none'"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-009" not in rule_ids


# ===========================================================================
# Section 10 – HDR-010: CSP contains unsafe-inline or unsafe-eval
# ===========================================================================

class TestHdr010:
    """HDR-010 fires when CSP includes 'unsafe-inline' or 'unsafe-eval'."""

    def test_fires_on_unsafe_inline(self, pack):
        headers = dict(_clean_headers())
        headers["Content-Security-Policy"] = "default-src 'self'; script-src 'unsafe-inline'"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-010" in rule_ids

    def test_fires_on_unsafe_eval(self, pack):
        headers = dict(_clean_headers())
        headers["Content-Security-Policy"] = "default-src 'self'; script-src 'unsafe-eval'"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-010" in rule_ids

    def test_fires_on_both_unsafe_directives(self, pack):
        headers = dict(_clean_headers())
        headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'"
        )
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-010" in rule_ids

    def test_does_not_fire_on_safe_csp(self, pack):
        result = pack.evaluate(_clean_headers())
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-010" not in rule_ids

    def test_does_not_fire_when_csp_absent(self, pack):
        # When CSP is absent, HDR-003 fires, but not HDR-010.
        headers = dict(_clean_headers())
        del headers["Content-Security-Policy"]
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-010" not in rule_ids

    def test_case_insensitive_unsafe_inline_value(self, pack):
        # The check must detect uppercase variants inside the CSP value.
        headers = dict(_clean_headers())
        headers["Content-Security-Policy"] = "default-src 'self'; script-src 'UNSAFE-INLINE'"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-010" in rule_ids

    def test_case_insensitive_unsafe_eval_value(self, pack):
        headers = dict(_clean_headers())
        headers["Content-Security-Policy"] = "default-src 'self'; script-src 'Unsafe-Eval'"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-010" in rule_ids

    def test_severity_is_high(self, pack):
        headers = dict(_clean_headers())
        headers["Content-Security-Policy"] = "default-src 'self'; script-src 'unsafe-inline'"
        result = pack.evaluate(headers)
        match = next(m for m in result.matches if m.rule_id == "HDR-010")
        assert match.severity == HeaderSeverity.HIGH

    def test_evidence_contains_csp_value(self, pack):
        csp_val = "default-src 'self'; script-src 'unsafe-inline'"
        headers = dict(_clean_headers())
        headers["Content-Security-Policy"] = csp_val
        result = pack.evaluate(headers)
        match = next(m for m in result.matches if m.rule_id == "HDR-010")
        assert csp_val in match.evidence


# ===========================================================================
# Section 11 – Happy path: fully hardened headers produce zero findings
# ===========================================================================

class TestHappyPath:
    """A fully hardened header dict must produce no findings."""

    def test_clean_headers_produce_no_matches(self, pack):
        result = pack.evaluate(_clean_headers())
        assert result.total_matches == 0

    def test_clean_headers_risk_score_is_zero(self, pack):
        result = pack.evaluate(_clean_headers())
        assert result.risk_score == 0

    def test_clean_headers_headers_analyzed_count(self, pack):
        headers = _clean_headers()
        result = pack.evaluate(headers)
        assert result.headers_analyzed == len(headers)


# ===========================================================================
# Section 12 – HeaderResult structure and properties
# ===========================================================================

class TestHeaderResult:
    """Tests for HeaderResult properties, summary, and to_dict()."""

    def _result_with_multiple_findings(self, pack) -> HeaderResult:
        """Produce a result that has several findings."""
        headers = {
            "Content-Type": "text/html",
            "Server": "Apache/2.4.52",
            "X-Powered-By": "PHP/8.1.0",
        }
        return pack.evaluate(headers)

    def test_total_matches_equals_len_matches(self, pack):
        result = self._result_with_multiple_findings(pack)
        assert result.total_matches == len(result.matches)

    def test_critical_matches_property(self, pack):
        result = self._result_with_multiple_findings(pack)
        for m in result.critical_matches:
            assert m.severity == HeaderSeverity.CRITICAL

    def test_high_matches_property(self, pack):
        result = self._result_with_multiple_findings(pack)
        for m in result.high_matches:
            assert m.severity == HeaderSeverity.HIGH

    def test_matches_by_rule_returns_correct_subset(self, pack):
        result = self._result_with_multiple_findings(pack)
        subset = result.matches_by_rule("HDR-007")
        for m in subset:
            assert m.rule_id == "HDR-007"

    def test_matches_by_rule_unknown_id_returns_empty(self, pack):
        result = self._result_with_multiple_findings(pack)
        assert result.matches_by_rule("HDR-999") == []

    def test_summary_contains_total_matches(self, pack):
        result = self._result_with_multiple_findings(pack)
        assert str(result.total_matches) in result.summary()

    def test_summary_contains_risk_score(self, pack):
        result = self._result_with_multiple_findings(pack)
        assert str(result.risk_score) in result.summary()

    def test_to_dict_keys_present(self, pack):
        result = self._result_with_multiple_findings(pack)
        d = result.to_dict()
        for key in ("risk_score", "total_matches", "headers_analyzed", "generated_at", "matches"):
            assert key in d, f"Expected key '{key}' in to_dict() output"

    def test_to_dict_matches_is_list_of_dicts(self, pack):
        result = self._result_with_multiple_findings(pack)
        d = result.to_dict()
        assert isinstance(d["matches"], list)
        for item in d["matches"]:
            assert isinstance(item, dict)

    def test_headers_analyzed_correct_count(self, pack):
        headers = {"A": "1", "B": "2", "C": "3"}
        result = pack.evaluate(headers)
        assert result.headers_analyzed == 3


# ===========================================================================
# Section 13 – HeaderMatch structure
# ===========================================================================

class TestHeaderMatch:
    """Tests for HeaderMatch.to_dict() and summary()."""

    def _one_match(self, pack) -> HeaderMatch:
        headers = dict(_clean_headers())
        del headers["X-Frame-Options"]
        result = pack.evaluate(headers)
        return next(m for m in result.matches if m.rule_id == "HDR-004")

    def test_to_dict_contains_required_keys(self, pack):
        m = self._one_match(pack)
        d = m.to_dict()
        for key in ("rule_id", "severity", "title", "detail", "evidence", "remediation"):
            assert key in d, f"Expected key '{key}' in HeaderMatch.to_dict()"

    def test_to_dict_severity_is_string(self, pack):
        m = self._one_match(pack)
        d = m.to_dict()
        assert isinstance(d["severity"], str)

    def test_summary_contains_rule_id(self, pack):
        m = self._one_match(pack)
        assert m.rule_id in m.summary()

    def test_summary_contains_severity(self, pack):
        m = self._one_match(pack)
        assert m.severity.value in m.summary()


# ===========================================================================
# Section 14 – Risk score calculation and capping
# ===========================================================================

class TestRiskScore:
    """Risk score accumulates per-rule weights and caps at 100."""

    def test_risk_score_zero_for_clean_headers(self, pack):
        result = pack.evaluate(_clean_headers())
        assert result.risk_score == 0

    def test_risk_score_matches_expected_weight_for_single_rule(self, pack):
        # Only HDR-008 (X-Powered-By, weight=15) should fire for this input.
        headers = dict(_clean_headers())
        headers["X-Powered-By"] = "Express"
        result = pack.evaluate(headers)
        assert result.risk_score == _RULE_WEIGHTS["HDR-008"]

    def test_risk_score_capped_at_100(self, pack):
        # Provide a header set designed to fire many high-weight rules.
        headers = {
            "Content-Type": "text/html",
            # Missing HSTS (35) + Missing CSP (30) + Missing XFO (25)
            # + Missing XCTO (20) + Missing Referrer-Policy (15)
            # + Server version leak (20) + X-Powered-By (15)
            # + Missing Permissions-Policy (10)
            # = 170 raw → capped at 100
            "Server": "Apache/2.4.52",
            "X-Powered-By": "PHP/8.1.0",
        }
        result = pack.evaluate(headers)
        assert result.risk_score <= 100

    def test_risk_score_is_non_negative(self, pack):
        result = pack.evaluate({})
        assert result.risk_score >= 0

    def test_duplicate_rules_do_not_double_count(self, pack):
        # Each rule can only contribute its weight once even if (by
        # construction) it could somehow appear twice—this is an invariant
        # of the implementation.
        headers = {"Content-Type": "text/html"}
        result = pack.evaluate(headers)
        # Collect unique fired rule_ids and manually sum weights.
        unique_ids = set(m.rule_id for m in result.matches)
        expected = min(sum(_RULE_WEIGHTS.get(rid, 0) for rid in unique_ids), 100)
        assert result.risk_score == expected


# ===========================================================================
# Section 15 – evaluate_many() batch method
# ===========================================================================

class TestEvaluateMany:
    """evaluate_many() returns one HeaderResult per input dict."""

    def test_returns_correct_number_of_results(self, pack):
        inputs = [_clean_headers(), {"Content-Type": "text/html"}, _clean_headers()]
        results = pack.evaluate_many(inputs)
        assert len(results) == len(inputs)

    def test_each_result_is_headerresult(self, pack):
        results = pack.evaluate_many([_clean_headers(), {}])
        for r in results:
            assert isinstance(r, HeaderResult)

    def test_clean_headers_result_has_no_matches(self, pack):
        results = pack.evaluate_many([_clean_headers()])
        assert results[0].total_matches == 0

    def test_empty_headers_result_has_matches(self, pack):
        results = pack.evaluate_many([{}])
        assert results[0].total_matches > 0

    def test_empty_list_returns_empty_list(self, pack):
        assert pack.evaluate_many([]) == []

    def test_results_are_independent(self, pack):
        headers_a = dict(_clean_headers())
        headers_b = {"Content-Type": "text/html", "Server": "Apache/2.4.52"}
        results = pack.evaluate_many([headers_a, headers_b])
        assert results[0].risk_score == 0
        assert results[1].risk_score > 0

    def test_batch_order_preserved(self, pack):
        inputs = [
            {"Content-Type": "text/html", "Server": "nginx/1.22.0"},
            _clean_headers(),
        ]
        results = pack.evaluate_many(inputs)
        # First result should have HDR-007 (server version leak).
        rule_ids_first = [m.rule_id for m in results[0].matches]
        assert "HDR-007" in rule_ids_first
        # Second result should be clean.
        assert results[1].total_matches == 0


# ===========================================================================
# Section 16 – Optional flags (require_csp, require_hsts,
#               require_permissions_policy)
# ===========================================================================

class TestOptionalFlags:
    """Turning off optional requirements suppresses the related checks."""

    def test_require_csp_false_suppresses_hdr003(self):
        pack = HeaderSecurityPack(require_csp=False)
        headers = dict(_clean_headers())
        del headers["Content-Security-Policy"]
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-003" not in rule_ids

    def test_require_csp_false_does_not_suppress_hdr010(self):
        # HDR-010 fires independently of the require_csp flag.
        pack = HeaderSecurityPack(require_csp=False)
        headers = dict(_clean_headers())
        headers["Content-Security-Policy"] = "default-src 'self'; script-src 'unsafe-inline'"
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-010" in rule_ids

    def test_require_hsts_false_suppresses_hdr001(self):
        pack = HeaderSecurityPack(require_hsts=False)
        result = pack.evaluate({"Content-Type": "text/html"})
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-001" not in rule_ids

    def test_require_permissions_policy_false_suppresses_hdr009(self):
        pack = HeaderSecurityPack(require_permissions_policy=False)
        headers = dict(_clean_headers())
        del headers["Permissions-Policy"]
        result = pack.evaluate(headers)
        rule_ids = [m.rule_id for m in result.matches]
        assert "HDR-009" not in rule_ids

    def test_all_flags_false_reduces_findings(self):
        pack = HeaderSecurityPack(
            require_hsts=False,
            require_csp=False,
            require_permissions_policy=False,
        )
        headers = {"Content-Type": "text/html"}
        result = pack.evaluate(headers)
        # HDR-001, HDR-002, HDR-003, HDR-009 are suppressed; others may fire.
        suppressed = {"HDR-001", "HDR-002", "HDR-003", "HDR-009"}
        for rule_id in suppressed:
            assert rule_id not in [m.rule_id for m in result.matches]
