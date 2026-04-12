"""Unit tests for the WAF coverage analyzer."""
import pytest
from shared.validators.coverage_analyzer import (
    OWASP_CATEGORIES,
    analyze_coverage,
    CoverageReport,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pack(category: str, mode: str = "block", vendor: str = "cloudflare") -> dict:
    return {
        "name": f"Test pack ({category})",
        "vendor": vendor,
        "category": category,
        "objective": "Test pack for unit tests only",
        "risk_mitigated": "Test risk",
        "severity": "high",
        "mode": mode,
        "version": "1.0.0",
        "maturity": "reviewed",
    }


# ---------------------------------------------------------------------------
# Basic coverage
# ---------------------------------------------------------------------------


def test_empty_pack_list_returns_zero_score():
    report = analyze_coverage([])
    assert report.score == 0
    assert len(report.gaps) == len(OWASP_CATEGORIES)
    assert report.packs_analyzed == 0


def test_sqli_pack_covers_a03():
    report = analyze_coverage([_pack("sqli_protection")])
    assert "A03" in report.covered_categories
    assert report.score > 0


def test_xss_pack_also_covers_a03():
    report = analyze_coverage([_pack("xss_protection")])
    assert "A03" in report.covered_categories


def test_rate_limiting_covers_a07():
    report = analyze_coverage([_pack("rate_limiting")])
    assert "A07" in report.covered_categories


def test_ssrf_covers_both_a04_and_a10():
    report = analyze_coverage([_pack("ssrf_protection")])
    assert "A04" in report.covered_categories
    assert "A10" in report.covered_categories


def test_header_hardening_covers_a02_and_a05():
    report = analyze_coverage([_pack("header_hardening")])
    assert "A02" in report.covered_categories
    assert "A05" in report.covered_categories


def test_security_headers_covers_a02_and_a05():
    report = analyze_coverage([_pack("security_headers")])
    assert "A02" in report.covered_categories
    assert "A05" in report.covered_categories


def test_authentication_protection_covers_a07():
    report = analyze_coverage([_pack("authentication_protection")])
    assert "A07" in report.covered_categories


def test_lfi_rfi_protection_covers_a03():
    report = analyze_coverage([_pack("lfi_rfi_protection")])
    assert "A03" in report.covered_categories


# ---------------------------------------------------------------------------
# Mode filtering
# ---------------------------------------------------------------------------


def test_log_only_pack_does_not_count_as_covered():
    """A pack in log-only mode should not contribute to coverage score."""
    report = analyze_coverage([_pack("sqli_protection", mode="log")])
    assert "A03" not in report.covered_categories
    assert report.score == 0
    assert report.active_packs == 0


def test_block_mode_counts_as_active():
    report = analyze_coverage([_pack("sqli_protection", mode="block")])
    assert report.active_packs == 1


def test_challenge_mode_counts_as_active():
    report = analyze_coverage([_pack("rate_limiting", mode="js_challenge")])
    assert report.active_packs == 1
    assert "A07" in report.covered_categories


def test_security_headers_log_mode_counts_as_protective():
    report = analyze_coverage([_pack("security_headers", mode="log")])
    assert report.active_packs == 1
    assert "A02" in report.covered_categories
    assert "A05" in report.covered_categories


# ---------------------------------------------------------------------------
# Multiple packs and cumulative scoring
# ---------------------------------------------------------------------------


def test_multiple_packs_accumulate_score():
    packs = [
        _pack("sqli_protection"),    # A03
        _pack("rate_limiting"),      # A07
        _pack("ssrf_protection"),    # A04 + A10
        _pack("header_hardening"),   # A02 + A05
        _pack("admin_protection"),   # A01
    ]
    report = analyze_coverage(packs)
    assert report.score > 50
    # All covered categories from above should be present
    for owasp_id in ["A01", "A02", "A03", "A04", "A05", "A07", "A10"]:
        assert owasp_id in report.covered_categories


def test_duplicate_category_only_counted_once():
    """Two packs covering the same category should not double the score."""
    packs = [_pack("sqli_protection"), _pack("sqli_protection")]
    report = analyze_coverage(packs)
    # A03 weight = 20, should be counted once
    a03 = next(c for c in OWASP_CATEGORIES if c.owasp_id == "A03")
    assert report.score == a03.weight


# ---------------------------------------------------------------------------
# Vendor breakdown
# ---------------------------------------------------------------------------


def test_vendor_breakdown_counts_active_packs():
    packs = [
        _pack("sqli_protection", vendor="cloudflare"),
        _pack("xss_protection", vendor="cloudflare"),
        _pack("rate_limiting", vendor="aws-waf"),
    ]
    report = analyze_coverage(packs)
    assert report.vendor_breakdown.get("cloudflare") == 2
    assert report.vendor_breakdown.get("aws-waf") == 1


# ---------------------------------------------------------------------------
# Gaps
# ---------------------------------------------------------------------------


def test_uncovered_categories_appear_as_gaps():
    # Only cover A03 — all others should be gaps
    report = analyze_coverage([_pack("sqli_protection")])
    gap_ids = {g.owasp_id for g in report.gaps}
    assert "A03" not in gap_ids
    assert "A07" in gap_ids  # rate limiting not covered


def test_gap_has_recommendation():
    report = analyze_coverage([])
    for gap in report.gaps:
        assert gap.recommendation
        assert len(gap.recommendation) > 10


# ---------------------------------------------------------------------------
# Rating
# ---------------------------------------------------------------------------


def test_rating_strong():
    # Cover most categories to hit >= 80
    packs = [
        _pack("sqli_protection"),   # A03: 20
        _pack("xss_protection"),    # A03: already covered
        _pack("rate_limiting"),     # A07: 12
        _pack("ssrf_protection"),   # A04+A10: 10+10
        _pack("header_hardening"),  # A02+A05: 8+10
        _pack("admin_protection"),  # A01: 15
        _pack("scanner_detection"), # A06: 5
    ]
    report = analyze_coverage(packs)
    # Total covered: A01(15)+A02(8)+A03(20)+A04(10)+A05(10)+A06(5)+A07(12)+A10(10) = 90
    assert report.score >= 80
    assert report.rating == "Strong"


def test_rating_weak():
    report = analyze_coverage([])
    assert report.rating == "Weak"


# ---------------------------------------------------------------------------
# passed / gap_weight_total
# ---------------------------------------------------------------------------


def test_gap_weight_total_plus_score_equals_100_when_full():
    """For any analysis, covered + gap weights should sum to 100."""
    packs = [_pack("sqli_protection"), _pack("rate_limiting")]
    report = analyze_coverage(packs)
    assert report.score + report.gap_weight_total == 100
