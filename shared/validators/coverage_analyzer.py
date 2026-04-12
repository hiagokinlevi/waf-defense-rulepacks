"""
WAF Coverage Analyzer
======================
Analyzes a collection of deployed WAF rule packs to identify coverage gaps
and compute a protection score across major OWASP attack categories.

Given a directory of pack JSON files (or a list of pack dicts), the analyzer:
  1. Maps each pack's category field to one or more OWASP Top 10 categories
  2. Identifies which OWASP categories have no coverage
  3. Produces a coverage score (0–100) and a gap report

Scoring model:
  - Each OWASP category has a weight (total weights sum to 100)
  - A category is "covered" if at least one deployed pack has an aligned category
    AND the pack contributes active protection. Most categories require
    block/challenge-style modes, while response-hardening packs such as
    security headers can still count when metadata uses 'log' because the
    underlying control is enforced through a transform rule.
  - Score = sum of weights of covered categories

Usage:
    from shared.validators.coverage_analyzer import analyze_coverage, CoverageReport

    report = analyze_coverage(Path("cloudflare/waf-rules"))
    print(f"Score: {report.score}/100")
    for gap in report.gaps:
        print(f"  GAP [{gap.owasp_id}]: {gap.name}")
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# OWASP Top 10 (2021) category definitions with weights
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class OwaspCategory:
    owasp_id: str         # e.g. "A01"
    name: str             # e.g. "Broken Access Control"
    weight: int           # Contribution to total score (weights sum to 100)
    pack_categories: frozenset[str]  # Pack category values that cover this OWASP item


OWASP_CATEGORIES: list[OwaspCategory] = [
    OwaspCategory(
        owasp_id="A01",
        name="Broken Access Control",
        weight=15,
        pack_categories=frozenset({"access_control", "admin_protection", "path_traversal"}),
    ),
    OwaspCategory(
        owasp_id="A02",
        name="Cryptographic Failures",
        weight=8,
        pack_categories=frozenset({"tls_enforcement", "header_hardening", "security_headers"}),
    ),
    OwaspCategory(
        owasp_id="A03",
        name="Injection (SQLi, XSS, etc.)",
        weight=20,
        pack_categories=frozenset(
            {"sqli_protection", "xss_protection", "command_injection", "injection", "lfi_rfi_protection"}
        ),
    ),
    OwaspCategory(
        owasp_id="A04",
        name="Insecure Design (SSRF, etc.)",
        weight=10,
        pack_categories=frozenset({"ssrf_protection", "request_forgery"}),
    ),
    OwaspCategory(
        owasp_id="A05",
        name="Security Misconfiguration",
        weight=10,
        pack_categories=frozenset(
            {"header_hardening", "security_headers", "default_credential_protection", "security_misconfiguration"}
        ),
    ),
    OwaspCategory(
        owasp_id="A06",
        name="Vulnerable and Outdated Components",
        weight=5,
        pack_categories=frozenset({"scanner_detection", "vulnerability_scanner"}),
    ),
    OwaspCategory(
        owasp_id="A07",
        name="Identification and Authentication Failures",
        weight=12,
        pack_categories=frozenset(
            {"rate_limiting", "brute_force_protection", "credential_stuffing", "authentication_protection"}
        ),
    ),
    OwaspCategory(
        owasp_id="A08",
        name="Software and Data Integrity Failures",
        weight=5,
        pack_categories=frozenset({"supply_chain", "deserialization", "integrity_checks"}),
    ),
    OwaspCategory(
        owasp_id="A09",
        name="Security Logging and Monitoring Failures",
        weight=5,
        pack_categories=frozenset({"logging", "monitoring", "anomaly_detection"}),
    ),
    OwaspCategory(
        owasp_id="A10",
        name="Server-Side Request Forgery (SSRF)",
        weight=10,
        pack_categories=frozenset({"ssrf_protection", "request_forgery"}),
    ),
]

# Modes that count as active blocking (not just observation)
ACTIVE_MODES = {"block", "challenge", "js_challenge", "managed_challenge"}

# Some controls provide active protection even when pack metadata uses "log"
# because the underlying WAF primitive is not a request-blocking action.
NON_BLOCKING_PROTECTIVE_CATEGORIES = {"security_headers"}


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class CoverageGap:
    owasp_id: str
    name: str
    weight: int
    recommendation: str


@dataclass
class PackSummary:
    name: str
    vendor: str
    category: str
    mode: str
    maturity: str
    owasp_coverage: list[str]  # List of OWASP IDs this pack contributes to


@dataclass
class CoverageReport:
    """Full coverage analysis result."""

    packs_analyzed: int
    active_packs: int               # Packs contributing active protection to the score
    score: int                       # 0–100 coverage score
    covered_categories: list[str]    # OWASP IDs with coverage
    gaps: list[CoverageGap]          # OWASP IDs with no coverage
    pack_summaries: list[PackSummary]
    vendor_breakdown: dict[str, int] # vendor → count of active packs
    warnings: list[str]             # Non-fatal issues found during analysis

    @property
    def rating(self) -> str:
        """Human-readable rating based on score."""
        if self.score >= 80:
            return "Strong"
        if self.score >= 60:
            return "Moderate"
        if self.score >= 40:
            return "Basic"
        return "Weak"

    @property
    def gap_weight_total(self) -> int:
        """Sum of weights for uncovered categories."""
        return sum(g.weight for g in self.gaps)


# ---------------------------------------------------------------------------
# Analysis logic
# ---------------------------------------------------------------------------

def _counts_toward_coverage(category: str, mode: str) -> bool:
    """Return True when a pack meaningfully contributes to protection score."""
    if mode in ACTIVE_MODES:
        return True
    return category in NON_BLOCKING_PROTECTIVE_CATEGORIES and mode == "log"


def analyze_coverage(
    source: Path | list[dict],
    skip_patterns: Optional[list[str]] = None,
) -> CoverageReport:
    """
    Analyze WAF pack coverage across OWASP Top 10 categories.

    Args:
        source: Either a directory path (scans all *.json files, excluding
                schemas/terraform/examples) or a list of pack dicts for testing.
        skip_patterns: Additional directory/filename patterns to skip.

    Returns:
        CoverageReport with score, gaps, and per-pack summaries.
    """
    _skip = set(["schemas", "terraform", "examples", ".git"])
    if skip_patterns:
        _skip.update(skip_patterns)

    packs: list[dict] = []
    warnings: list[str] = []

    if isinstance(source, list):
        packs = source
    else:
        # Load all JSON pack files from the directory
        for json_file in sorted(source.rglob("*.json")):
            if any(p in str(json_file) for p in _skip):
                continue
            try:
                data = json.loads(json_file.read_text())
            except (json.JSONDecodeError, OSError) as exc:
                warnings.append(f"Could not load {json_file}: {exc}")
                continue

            # Skip container files (those with _k1n_metadata at top level only)
            if "_k1n_metadata" in data and len(data) <= 2:
                continue

            # Skip files that look like Terraform or other non-pack files
            if "name" not in data or "category" not in data:
                continue

            packs.append(data)

    if not packs:
        warnings.append("No valid pack files found to analyze")

    # Build coverage map: owasp_id → bool
    pack_summaries: list[PackSummary] = []
    covered: dict[str, bool] = {cat.owasp_id: False for cat in OWASP_CATEGORIES}
    vendor_breakdown: dict[str, int] = {}
    active_count = 0

    for pack in packs:
        category = pack.get("category", "").lower()
        mode = pack.get("mode", "log").lower()
        vendor = pack.get("vendor", "unknown")
        maturity = pack.get("maturity", "draft")
        name = pack.get("name", "unnamed")

        is_active = _counts_toward_coverage(category, mode)
        if is_active:
            active_count += 1
            vendor_breakdown[vendor] = vendor_breakdown.get(vendor, 0) + 1

        owasp_contributions: list[str] = []

        for owasp_cat in OWASP_CATEGORIES:
            if category in owasp_cat.pack_categories:
                owasp_contributions.append(owasp_cat.owasp_id)
                # Only count packs that provide active protection toward coverage
                if is_active:
                    covered[owasp_cat.owasp_id] = True

        if not owasp_contributions and is_active:
            warnings.append(
                f"Pack '{name}' (category='{category}') does not map to any OWASP category — "
                "consider adding it to OWASP_CATEGORIES or reviewing the category value"
            )

        pack_summaries.append(PackSummary(
            name=name,
            vendor=vendor,
            category=category,
            mode=mode,
            maturity=maturity,
            owasp_coverage=owasp_contributions,
        ))

    # Compute score and gaps
    score = sum(cat.weight for cat in OWASP_CATEGORIES if covered[cat.owasp_id])
    covered_ids = [cat.owasp_id for cat in OWASP_CATEGORIES if covered[cat.owasp_id]]

    _gap_recommendations: dict[str, str] = {
        "A01": "Add admin path protection and path traversal blocking rules",
        "A02": "Add TLS enforcement headers (HSTS, Content-Security-Policy) via a security-headers pack",
        "A03": "Add SQLi and XSS blocking rules for all ingress points",
        "A04": "Add SSRF mitigation rules to restrict outbound server-side requests",
        "A05": "Add a security headers pack (X-Frame-Options, X-Content-Type-Options, HSTS)",
        "A06": "Add scanner and crawler detection rules to identify reconnaissance activity",
        "A07": "Add rate-limiting rules for login, registration, and password-reset endpoints",
        "A08": "Add rules to detect and block unsafe deserialization payloads",
        "A09": "Enable WAF logging and configure alerting on spike detection",
        "A10": "Add SSRF rules to block internal metadata endpoints (169.254.x.x, 10.x.x.x from URI)",
    }

    gaps = [
        CoverageGap(
            owasp_id=cat.owasp_id,
            name=cat.name,
            weight=cat.weight,
            recommendation=_gap_recommendations.get(cat.owasp_id, "Add coverage for this category"),
        )
        for cat in OWASP_CATEGORIES
        if not covered[cat.owasp_id]
    ]

    return CoverageReport(
        packs_analyzed=len(packs),
        active_packs=active_count,
        score=score,
        covered_categories=covered_ids,
        gaps=gaps,
        pack_summaries=pack_summaries,
        vendor_breakdown=vendor_breakdown,
        warnings=warnings,
    )


def print_report(report: CoverageReport, verbose: bool = False) -> None:
    """Print a formatted coverage report to stdout."""
    print(f"\n{'='*60}")
    print(f"  WAF Coverage Analysis Report")
    print(f"{'='*60}")
    print(f"  Score:          {report.score}/100 ({report.rating})")
    print(f"  Packs analyzed: {report.packs_analyzed} total / {report.active_packs} protective")
    print(f"  Covered OWASP:  {len(report.covered_categories)}/10 categories")
    print(f"  Gap weight:     {report.gap_weight_total} points uncovered")

    if report.vendor_breakdown:
        vendors = ", ".join(f"{v}: {c}" for v, c in sorted(report.vendor_breakdown.items()))
        print(f"  Vendors:        {vendors}")

    if report.gaps:
        print(f"\n  COVERAGE GAPS ({len(report.gaps)}):")
        for gap in report.gaps:
            print(f"    [{gap.owasp_id}] {gap.name} (weight: {gap.weight})")
            print(f"         → {gap.recommendation}")

    if verbose and report.pack_summaries:
        print(f"\n  PROTECTIVE PACK DETAILS:")
        for ps in report.pack_summaries:
            if _counts_toward_coverage(ps.category, ps.mode):
                owasp = ", ".join(ps.owasp_coverage) if ps.owasp_coverage else "unmapped"
                print(f"    {ps.name[:50]:<50} [{ps.vendor}] covers: {owasp}")

    if report.warnings:
        print(f"\n  WARNINGS:")
        for w in report.warnings:
            print(f"    ! {w}")

    print(f"{'='*60}\n")
