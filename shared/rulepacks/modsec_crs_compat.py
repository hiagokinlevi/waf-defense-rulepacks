"""
ModSecurity CRS Rule Compatibility Layer
=========================================
Maps ModSecurity Core Rule Set (CRS) rule IDs to equivalent protection
categories in Cloudflare WAF, AWS WAF managed rule groups, and Azure WAF
managed rule sets.

This module enables teams migrating from ModSecurity/CRS to a cloud WAF to:
  1. Look up what each CRS rule ID protects against
  2. Find the nearest equivalent managed rule group in their target platform
  3. Identify CRS rules with no managed equivalent (requiring custom rules)
  4. Generate a migration gap report

CRS version targeted: 4.x (OWASP CRS 4.0 / 4.1 / 4.2)

Usage:
    from shared.rulepacks.modsec_crs_compat import (
        CrsRuleMapping,
        CRS_RULE_MAP,
        lookup_crs_rule,
        get_cloudflare_equivalent,
        get_aws_equivalent,
        get_azure_equivalent,
        generate_migration_gap_report,
    )

    mapping = lookup_crs_rule(942100)
    print(mapping.description)
    print(get_aws_equivalent(942100))
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# CRS rule mapping dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CrsRuleMapping:
    """
    Mapping entry for a single CRS rule ID (or ID range).

    Attributes:
        rule_id:         Numeric CRS rule ID (or start of range).
        rule_id_end:     End of range (inclusive). None if single rule.
        category:        Short category label (e.g., "sqli", "xss", "rfi").
        description:     What the rule protects against.
        owasp_category:  Mapped OWASP Top 10 (2021) category ID.
        severity:        CRS paranoia level / severity (1=highest, 4=lowest).
        cloudflare_equivalent: Cloudflare managed ruleset group name(s).
        aws_equivalent:        AWS WAF managed rule group ARN fragment(s).
        azure_equivalent:      Azure WAF (DRS/CRS) rule group name(s).
        notes:           Migration notes (gaps, limitations, caveats).
    """
    rule_id:              int
    rule_id_end:          Optional[int]
    category:             str
    description:          str
    owasp_category:       str
    severity:             int                  # 1 = critical, 4 = informational
    cloudflare_equivalent: list[str]           = field(default_factory=list)
    aws_equivalent:        list[str]           = field(default_factory=list)
    azure_equivalent:      list[str]           = field(default_factory=list)
    notes:                str                  = ""

    def covers(self, rule_id: int) -> bool:
        """Return True if this mapping covers the given CRS rule ID."""
        if self.rule_id_end is not None:
            return self.rule_id <= rule_id <= self.rule_id_end
        return rule_id == self.rule_id

    @property
    def has_cloudflare_equivalent(self) -> bool:
        return bool(self.cloudflare_equivalent)

    @property
    def has_aws_equivalent(self) -> bool:
        return bool(self.aws_equivalent)

    @property
    def has_azure_equivalent(self) -> bool:
        return bool(self.azure_equivalent)

    @property
    def is_fully_covered(self) -> bool:
        """True if all three major platforms have an equivalent."""
        return (
            self.has_cloudflare_equivalent
            and self.has_aws_equivalent
            and self.has_azure_equivalent
        )


# ---------------------------------------------------------------------------
# CRS rule map (representative subset covering the most critical rule ranges)
# ---------------------------------------------------------------------------
# CRS rule ID ranges (https://coreruleset.org/docs/rules/):
#   900xxx — Initialization
#   910xxx — IP reputation / block lists
#   911xxx — Method enforcement
#   912xxx — DoS protection
#   913xxx — Scanner detection
#   920xxx — Protocol enforcement
#   921xxx — Protocol attack
#   930xxx — Local file inclusion (LFI)
#   931xxx — Remote file inclusion (RFI)
#   932xxx — Remote code execution (RCE)
#   933xxx — PHP injection
#   934xxx — Node.js injection
#   941xxx — XSS / HTML injection
#   942xxx — SQL injection
#   943xxx — Session fixation
#   944xxx — Java attacks
#   949xxx — Blocking evaluation (anomaly scores)
#   959xxx — RESPONSE rules
#   980xxx — Correlation rules

CRS_RULE_MAP: list[CrsRuleMapping] = [
    # ------------------------------------------------------------------
    # SQL Injection (942xxx)
    # ------------------------------------------------------------------
    CrsRuleMapping(
        rule_id=942100,
        rule_id_end=942999,
        category="sqli",
        description="SQL injection attack detection (OWASP CRS SQLi rules, all sub-types)",
        owasp_category="A03",
        severity=1,
        cloudflare_equivalent=[
            "cloudflare_owasp_sqli",         # Cloudflare OWASP Core Ruleset — SQLi group
            "cloudflare_managed_sqli",        # Cloudflare Managed Ruleset — SQLi
        ],
        aws_equivalent=[
            "AWSManagedRulesSQLiRuleSet",     # AWS Managed Rules — SQL database group
        ],
        azure_equivalent=[
            "REQUEST-942-APPLICATION-ATTACK-SQLI",  # Azure DRS/CRS rule group
        ],
        notes=(
            "Full CRS paranoia level 1–4 coverage. Cloud WAF managed groups cover "
            "paranoia level 1–2 patterns. CRS paranoia 3–4 rules (aggressive detection) "
            "may require custom rules for equivalent coverage."
        ),
    ),

    # ------------------------------------------------------------------
    # Cross-Site Scripting (941xxx)
    # ------------------------------------------------------------------
    CrsRuleMapping(
        rule_id=941100,
        rule_id_end=941999,
        category="xss",
        description="Cross-site scripting (XSS) attack detection",
        owasp_category="A03",
        severity=1,
        cloudflare_equivalent=[
            "cloudflare_owasp_xss",
            "cloudflare_managed_xss",
        ],
        aws_equivalent=[
            "AWSManagedRulesCommonRuleSet",   # XSSBody, XSSQueryString rules
        ],
        azure_equivalent=[
            "REQUEST-941-APPLICATION-ATTACK-XSS",
        ],
        notes=(
            "Cloud WAF XSS detection focuses on URL/body patterns. "
            "CRS header-injection and DOM-based XSS rules (941xxx range 600+) "
            "may not have direct managed equivalents — add custom header rules."
        ),
    ),

    # ------------------------------------------------------------------
    # Local File Inclusion (930xxx)
    # ------------------------------------------------------------------
    CrsRuleMapping(
        rule_id=930100,
        rule_id_end=930999,
        category="lfi",
        description="Local file inclusion (LFI) and path traversal attack detection",
        owasp_category="A01",
        severity=1,
        cloudflare_equivalent=[
            "cloudflare_owasp_lfi",
        ],
        aws_equivalent=[
            "AWSManagedRulesCommonRuleSet",   # GenericLFI_URIPATH, GenericLFI_QueryArguments
        ],
        azure_equivalent=[
            "REQUEST-930-APPLICATION-ATTACK-LFI",
        ],
        notes=(
            "Path traversal sequences (../  and variants) are well-covered by all platforms. "
            "Null byte injection detection (CRS 930120) may require a custom rule on Azure."
        ),
    ),

    # ------------------------------------------------------------------
    # Remote File Inclusion (931xxx)
    # ------------------------------------------------------------------
    CrsRuleMapping(
        rule_id=931100,
        rule_id_end=931999,
        category="rfi",
        description="Remote file inclusion (RFI) attack detection",
        owasp_category="A01",
        severity=2,
        cloudflare_equivalent=[
            "cloudflare_owasp_rfi",
        ],
        aws_equivalent=[
            "AWSManagedRulesCommonRuleSet",   # GenericRFI_QUERYARGUMENTS, GenericRFI_BODY
        ],
        azure_equivalent=[
            "REQUEST-931-APPLICATION-ATTACK-RFI",
        ],
        notes="URL scheme detection (http://, ftp://) in parameter values is well-covered.",
    ),

    # ------------------------------------------------------------------
    # Remote Code Execution (932xxx)
    # ------------------------------------------------------------------
    CrsRuleMapping(
        rule_id=932100,
        rule_id_end=932999,
        category="rce",
        description="Remote OS command injection and code execution detection",
        owasp_category="A03",
        severity=1,
        cloudflare_equivalent=[
            "cloudflare_owasp_rce",
        ],
        aws_equivalent=[
            "AWSManagedRulesKnownBadInputsRuleSet",   # Log4JRCE, Host header injection
            "AWSManagedRulesCommonRuleSet",            # GenericRCE_QUERYARGUMENTS
        ],
        azure_equivalent=[
            "REQUEST-932-APPLICATION-ATTACK-RCE",
        ],
        notes=(
            "Shell metacharacter detection is covered. Platform-specific payloads "
            "(Windows cmd.exe patterns vs Unix shell patterns) — verify platform coverage "
            "matches your server OS."
        ),
    ),

    # ------------------------------------------------------------------
    # PHP Injection (933xxx)
    # ------------------------------------------------------------------
    CrsRuleMapping(
        rule_id=933100,
        rule_id_end=933999,
        category="php_injection",
        description="PHP injection and object injection attack detection",
        owasp_category="A03",
        severity=2,
        cloudflare_equivalent=[
            "cloudflare_owasp_php",
        ],
        aws_equivalent=[
            "AWSManagedRulesPHPRuleSet",
        ],
        azure_equivalent=[
            "REQUEST-933-APPLICATION-ATTACK-PHP",
        ],
        notes="AWS PHP rule group provides strong coverage. Verify PHP deserialization gadget chains.",
    ),

    # ------------------------------------------------------------------
    # Java Attacks (944xxx)
    # ------------------------------------------------------------------
    CrsRuleMapping(
        rule_id=944100,
        rule_id_end=944999,
        category="java_attacks",
        description="Java deserialization, Log4Shell, and Java-specific attack detection",
        owasp_category="A06",
        severity=1,
        cloudflare_equivalent=[
            "cloudflare_managed_log4shell",   # Cloudflare Log4J / CVE-2021-44228 specific
            "cloudflare_owasp_java",
        ],
        aws_equivalent=[
            "AWSManagedRulesKnownBadInputsRuleSet",   # Log4JRCE
        ],
        azure_equivalent=[
            "REQUEST-944-APPLICATION-ATTACK-JAVA",
        ],
        notes=(
            "Log4Shell (CVE-2021-44228) is covered by all platforms with dedicated rules. "
            "Java deserialization gadget chains (ysoserial payloads) coverage varies — "
            "AWS KnownBadInputs provides better coverage than CRS 944100-110."
        ),
    ),

    # ------------------------------------------------------------------
    # Scanner Detection (913xxx)
    # ------------------------------------------------------------------
    CrsRuleMapping(
        rule_id=913100,
        rule_id_end=913999,
        category="scanner_detection",
        description="Security scanner and vulnerability assessment tool detection",
        owasp_category="A05",
        severity=3,
        cloudflare_equivalent=[
            "cloudflare_managed_scanner_detection",
        ],
        aws_equivalent=[],  # No direct AWS managed equivalent
        azure_equivalent=[
            "REQUEST-913-SCANNER-DETECTION",
        ],
        notes=(
            "AWS WAF has no direct scanner detection managed rule group. "
            "Use Cloudflare Bot Management or custom AWS WAF rules matching "
            "common scanner User-Agent strings as a substitute."
        ),
    ),

    # ------------------------------------------------------------------
    # Protocol Enforcement (920xxx)
    # ------------------------------------------------------------------
    CrsRuleMapping(
        rule_id=920100,
        rule_id_end=920999,
        category="protocol_enforcement",
        description="HTTP protocol validation (invalid headers, encoding, methods)",
        owasp_category="A04",
        severity=2,
        cloudflare_equivalent=[
            "cloudflare_owasp_protocol",
        ],
        aws_equivalent=[
            "AWSManagedRulesCommonRuleSet",   # SizeRestrictions, NoUserAgent_HEADER
        ],
        azure_equivalent=[
            "REQUEST-920-PROTOCOL-ENFORCEMENT",
        ],
        notes=(
            "HTTP/0.9 and HTTP/1.0 enforcement may not be available in all cloud WAFs. "
            "Malformed Content-Type and Accept-Encoding checks need custom rules on AWS."
        ),
    ),

    # ------------------------------------------------------------------
    # DoS Protection (912xxx)
    # ------------------------------------------------------------------
    CrsRuleMapping(
        rule_id=912100,
        rule_id_end=912999,
        category="dos_protection",
        description="Denial of Service protection (HTTP flooding, Slowloris patterns)",
        owasp_category="A05",
        severity=2,
        cloudflare_equivalent=[
            "cloudflare_rate_limiting",       # Cloudflare rate limiting rules
            "cloudflare_ddos_managed",        # Cloudflare DDoS managed ruleset
        ],
        aws_equivalent=[
            "AWSManagedRulesAmazonIpReputationList",  # Rate limiting is external (Shield)
        ],
        azure_equivalent=[
            "REQUEST-912-DOS-PROTECTION",
        ],
        notes=(
            "CRS 912xxx DoS rules implement request counting at the WAF layer. "
            "Cloud platforms handle this differently: use dedicated rate limiting rules "
            "(separate from WAF managed rulesets) for equivalent protection. "
            "See rate_limit_rulepack.py for platform-specific rate limit configurations."
        ),
    ),

    # ------------------------------------------------------------------
    # Node.js Injection (934xxx)
    # ------------------------------------------------------------------
    CrsRuleMapping(
        rule_id=934100,
        rule_id_end=934999,
        category="nodejs_injection",
        description="Node.js prototype pollution and server-side template injection",
        owasp_category="A03",
        severity=2,
        cloudflare_equivalent=[
            "cloudflare_owasp_nodejs",
        ],
        aws_equivalent=[
            "AWSManagedRulesCommonRuleSet",   # Partial — SSJI patterns
        ],
        azure_equivalent=[
            "REQUEST-934-APPLICATION-ATTACK-GENERIC",
        ],
        notes=(
            "Prototype pollution via __proto__ and constructor.prototype is not natively "
            "covered by all managed rule groups. Add custom rules for "
            "JSON body inspection targeting __proto__ and constructor patterns."
        ),
    ),

    # ------------------------------------------------------------------
    # Session Fixation (943xxx)
    # ------------------------------------------------------------------
    CrsRuleMapping(
        rule_id=943100,
        rule_id_end=943999,
        category="session_fixation",
        description="Session fixation attack detection (PHP PHPSESSID injection)",
        owasp_category="A07",
        severity=2,
        cloudflare_equivalent=[
            "cloudflare_owasp_session_fixation",
        ],
        aws_equivalent=[],   # No direct managed equivalent
        azure_equivalent=[
            "REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION",
        ],
        notes=(
            "AWS WAF has no managed rule group for session fixation. "
            "Implement custom AWS WAF rules checking for PHP session ID injection "
            "in URL parameters as a substitute for CRS 943100."
        ),
    ),
]


# ---------------------------------------------------------------------------
# Lookup functions
# ---------------------------------------------------------------------------

def lookup_crs_rule(rule_id: int) -> Optional[CrsRuleMapping]:
    """
    Look up a CRS rule ID in the compatibility table.

    Args:
        rule_id: Numeric CRS rule ID (e.g., 942100).

    Returns:
        CrsRuleMapping if found, else None.
    """
    for mapping in CRS_RULE_MAP:
        if mapping.covers(rule_id):
            return mapping
    return None


def get_cloudflare_equivalent(rule_id: int) -> list[str]:
    """Return Cloudflare equivalent rule group names for a CRS rule ID."""
    mapping = lookup_crs_rule(rule_id)
    return mapping.cloudflare_equivalent if mapping else []


def get_aws_equivalent(rule_id: int) -> list[str]:
    """Return AWS WAF managed rule group names for a CRS rule ID."""
    mapping = lookup_crs_rule(rule_id)
    return mapping.aws_equivalent if mapping else []


def get_azure_equivalent(rule_id: int) -> list[str]:
    """Return Azure WAF rule group names for a CRS rule ID."""
    mapping = lookup_crs_rule(rule_id)
    return mapping.azure_equivalent if mapping else []


# ---------------------------------------------------------------------------
# Migration gap report
# ---------------------------------------------------------------------------

@dataclass
class MigrationGapReport:
    """
    Report of CRS-to-cloud-WAF migration gaps.

    Attributes:
        total_mappings:    Total CRS rule ranges in the compatibility table.
        fully_covered:     Count with equivalents on all three platforms.
        partial_coverage:  Count covered on some but not all platforms.
        no_coverage:       Count with no cloud equivalent on any platform.
        gaps:              List of (platform, CrsRuleMapping) for each gap.
        coverage_pct:      Percentage of mappings fully covered (0–100).
    """
    total_mappings:   int
    fully_covered:    int
    partial_coverage: int
    no_coverage:      int
    gaps:             list[tuple[str, CrsRuleMapping]]
    coverage_pct:     float


def generate_migration_gap_report(
    mappings: Optional[list[CrsRuleMapping]] = None,
) -> MigrationGapReport:
    """
    Analyze the CRS compatibility table and produce a gap report.

    Args:
        mappings: List of CrsRuleMapping to analyze. Defaults to CRS_RULE_MAP.

    Returns:
        MigrationGapReport summarizing coverage across all three platforms.
    """
    rules = mappings if mappings is not None else CRS_RULE_MAP
    if not rules:
        return MigrationGapReport(
            total_mappings=0, fully_covered=0, partial_coverage=0,
            no_coverage=0, gaps=[], coverage_pct=100.0,
        )

    fully_covered  = 0
    partial        = 0
    no_coverage    = 0
    gaps: list[tuple[str, CrsRuleMapping]] = []

    for m in rules:
        cf  = m.has_cloudflare_equivalent
        aws = m.has_aws_equivalent
        az  = m.has_azure_equivalent

        if cf and aws and az:
            fully_covered += 1
        elif not cf and not aws and not az:
            no_coverage += 1
            gaps.append(("all_platforms", m))
        else:
            partial += 1
            if not cf:
                gaps.append(("cloudflare", m))
            if not aws:
                gaps.append(("aws_waf", m))
            if not az:
                gaps.append(("azure_waf", m))

    return MigrationGapReport(
        total_mappings=len(rules),
        fully_covered=fully_covered,
        partial_coverage=partial,
        no_coverage=no_coverage,
        gaps=gaps,
        coverage_pct=round(fully_covered / len(rules) * 100, 1),
    )
