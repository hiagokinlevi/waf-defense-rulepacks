"""
Tests for shared/rulepacks/modsec_crs_compat.py

Validates:
  - lookup_crs_rule() finds mappings for known rule ID ranges
  - lookup_crs_rule() returns None for unknown IDs
  - get_cloudflare/aws/azure_equivalent() functions
  - CrsRuleMapping.covers() range and exact match logic
  - generate_migration_gap_report() structure and math
  - All CRS_RULE_MAP entries have non-empty category and description
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.rulepacks.modsec_crs_compat import (
    CRS_RULE_MAP,
    CrsRuleMapping,
    generate_migration_gap_report,
    get_aws_equivalent,
    get_azure_equivalent,
    get_cloudflare_equivalent,
    lookup_crs_rule,
)


# ---------------------------------------------------------------------------
# CrsRuleMapping.covers()
# ---------------------------------------------------------------------------

class TestCoversMethod:

    def test_exact_single_id_matches(self):
        m = CrsRuleMapping(
            rule_id=942100, rule_id_end=None,
            category="sqli", description="test", owasp_category="A03", severity=1,
        )
        assert m.covers(942100)
        assert not m.covers(942101)

    def test_range_covers_start(self):
        m = CrsRuleMapping(
            rule_id=942100, rule_id_end=942999,
            category="sqli", description="test", owasp_category="A03", severity=1,
        )
        assert m.covers(942100)

    def test_range_covers_end(self):
        m = CrsRuleMapping(
            rule_id=942100, rule_id_end=942999,
            category="sqli", description="test", owasp_category="A03", severity=1,
        )
        assert m.covers(942999)

    def test_range_covers_midpoint(self):
        m = CrsRuleMapping(
            rule_id=942100, rule_id_end=942999,
            category="sqli", description="test", owasp_category="A03", severity=1,
        )
        assert m.covers(942500)

    def test_range_excludes_before_start(self):
        m = CrsRuleMapping(
            rule_id=942100, rule_id_end=942999,
            category="sqli", description="test", owasp_category="A03", severity=1,
        )
        assert not m.covers(942099)

    def test_range_excludes_after_end(self):
        m = CrsRuleMapping(
            rule_id=942100, rule_id_end=942999,
            category="sqli", description="test", owasp_category="A03", severity=1,
        )
        assert not m.covers(943000)


# ---------------------------------------------------------------------------
# lookup_crs_rule
# ---------------------------------------------------------------------------

class TestLookupCrsRule:

    def test_sqli_range_found(self):
        result = lookup_crs_rule(942100)
        assert result is not None
        assert result.category == "sqli"

    def test_xss_range_found(self):
        result = lookup_crs_rule(941500)
        assert result is not None
        assert result.category == "xss"

    def test_lfi_range_found(self):
        result = lookup_crs_rule(930200)
        assert result is not None
        assert result.category == "lfi"

    def test_rce_range_found(self):
        result = lookup_crs_rule(932150)
        assert result is not None
        assert result.category == "rce"

    def test_java_attacks_found(self):
        result = lookup_crs_rule(944100)
        assert result is not None
        assert result.category == "java_attacks"

    def test_unknown_id_returns_none(self):
        assert lookup_crs_rule(999999) is None

    def test_unknown_low_id_returns_none(self):
        assert lookup_crs_rule(100) is None

    def test_boundary_inclusive(self):
        # 942999 should be in the sqli range
        result = lookup_crs_rule(942999)
        assert result is not None
        assert result.category == "sqli"


# ---------------------------------------------------------------------------
# Convenience equivalence functions
# ---------------------------------------------------------------------------

class TestEquivalenceFunctions:

    def test_get_cloudflare_sqli_not_empty(self):
        result = get_cloudflare_equivalent(942100)
        assert isinstance(result, list)
        assert len(result) > 0

    def test_get_aws_sqli_not_empty(self):
        result = get_aws_equivalent(942100)
        assert isinstance(result, list)
        assert len(result) > 0

    def test_get_azure_sqli_not_empty(self):
        result = get_azure_equivalent(942100)
        assert isinstance(result, list)
        assert len(result) > 0

    def test_unknown_id_returns_empty_list(self):
        assert get_cloudflare_equivalent(999999) == []
        assert get_aws_equivalent(999999) == []
        assert get_azure_equivalent(999999) == []

    def test_scanner_detection_no_aws_equivalent(self):
        """CRS scanner detection has no AWS managed equivalent."""
        result = get_aws_equivalent(913100)
        assert result == []


# ---------------------------------------------------------------------------
# CrsRuleMapping properties
# ---------------------------------------------------------------------------

class TestCrsRuleMappingProperties:

    def test_fully_covered_when_all_platforms_present(self):
        m = CrsRuleMapping(
            rule_id=942100, rule_id_end=942999, category="sqli",
            description="test", owasp_category="A03", severity=1,
            cloudflare_equivalent=["cf_sqli"],
            aws_equivalent=["aws_sqli"],
            azure_equivalent=["az_sqli"],
        )
        assert m.is_fully_covered

    def test_not_fully_covered_when_aws_missing(self):
        m = CrsRuleMapping(
            rule_id=942100, rule_id_end=None, category="sqli",
            description="test", owasp_category="A03", severity=1,
            cloudflare_equivalent=["cf"],
            aws_equivalent=[],
            azure_equivalent=["az"],
        )
        assert not m.is_fully_covered

    def test_has_cloudflare_false_when_empty(self):
        m = CrsRuleMapping(
            rule_id=1, rule_id_end=None, category="x", description="x",
            owasp_category="A01", severity=1, cloudflare_equivalent=[],
        )
        assert not m.has_cloudflare_equivalent


# ---------------------------------------------------------------------------
# CRS_RULE_MAP completeness
# ---------------------------------------------------------------------------

class TestCrsRuleMapCompleteness:

    def test_map_has_entries(self):
        assert len(CRS_RULE_MAP) >= 8

    def test_all_entries_have_category(self):
        for m in CRS_RULE_MAP:
            assert m.category, f"Rule {m.rule_id} has empty category"

    def test_all_entries_have_description(self):
        for m in CRS_RULE_MAP:
            assert m.description, f"Rule {m.rule_id} has empty description"

    def test_all_entries_have_valid_owasp_category(self):
        valid_owasp = {"A01", "A02", "A03", "A04", "A05", "A06", "A07",
                       "A08", "A09", "A10"}
        for m in CRS_RULE_MAP:
            assert m.owasp_category in valid_owasp, (
                f"Rule {m.rule_id} has invalid owasp_category: {m.owasp_category}"
            )

    def test_all_severities_in_range(self):
        for m in CRS_RULE_MAP:
            assert 1 <= m.severity <= 4, (
                f"Rule {m.rule_id} severity {m.severity} out of CRS range [1,4]"
            )

    def test_sqli_in_map(self):
        categories = {m.category for m in CRS_RULE_MAP}
        assert "sqli" in categories

    def test_xss_in_map(self):
        categories = {m.category for m in CRS_RULE_MAP}
        assert "xss" in categories


# ---------------------------------------------------------------------------
# generate_migration_gap_report
# ---------------------------------------------------------------------------

class TestGenerateMigrationGapReport:

    def test_report_total_matches_map(self):
        report = generate_migration_gap_report()
        assert report.total_mappings == len(CRS_RULE_MAP)

    def test_fully_covered_plus_partial_plus_no_coverage_equals_total(self):
        report = generate_migration_gap_report()
        assert (
            report.fully_covered + report.partial_coverage + report.no_coverage
            == report.total_mappings
        )

    def test_coverage_pct_in_valid_range(self):
        report = generate_migration_gap_report()
        assert 0.0 <= report.coverage_pct <= 100.0

    def test_empty_input_returns_100_pct(self):
        report = generate_migration_gap_report([])
        assert report.coverage_pct == 100.0
        assert report.total_mappings == 0

    def test_all_covered_input(self):
        fully_covered = [
            CrsRuleMapping(
                rule_id=1, rule_id_end=None, category="test",
                description="fully covered", owasp_category="A01", severity=1,
                cloudflare_equivalent=["cf"],
                aws_equivalent=["aws"],
                azure_equivalent=["az"],
            )
        ]
        report = generate_migration_gap_report(fully_covered)
        assert report.fully_covered == 1
        assert report.coverage_pct == 100.0
        assert len(report.gaps) == 0

    def test_partial_coverage_generates_gaps(self):
        """A rule missing AWS equivalent should generate an aws_waf gap."""
        partial = [
            CrsRuleMapping(
                rule_id=913100, rule_id_end=913999, category="scanner_detection",
                description="Scanner", owasp_category="A05", severity=3,
                cloudflare_equivalent=["cf"],
                aws_equivalent=[],       # gap
                azure_equivalent=["az"],
            )
        ]
        report = generate_migration_gap_report(partial)
        assert report.partial_coverage == 1
        assert any(platform == "aws_waf" for platform, _ in report.gaps)

    def test_default_crs_map_has_some_gaps(self):
        """The built-in map includes CRS rules without AWS equivalents (known gaps)."""
        report = generate_migration_gap_report()
        # scanner_detection and session_fixation have no AWS equivalent
        assert report.partial_coverage >= 1 or report.no_coverage >= 1
