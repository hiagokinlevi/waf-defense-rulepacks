# xml_security_pack.py
# ---------------------------------------------------------------------------
# Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# You are free to share and adapt this material for any purpose, even
# commercially, under the following terms:
#   Attribution — You must give appropriate credit, provide a link to the
#   license, and indicate if changes were made.
#
# Copyright (c) 2026 Cyber Port — hiagokinlevi
# ---------------------------------------------------------------------------
"""
XML Security Rulepack
=====================
Analyses raw XML string content for common XML-based attack patterns without
relying on any external XML parsing library.  All pattern matching is
performed with the stdlib ``re`` module only, making the rulepack safe to
deploy even in restricted environments where installing third-party packages
(``lxml``, ``defusedxml``) is not feasible.

Rule IDs
---------
XML-001   XXE via DOCTYPE with ENTITY declaration (CRITICAL)
XML-002   XML bomb / exponential entity expansion (HIGH)
XML-003   DTD external resource reference (HIGH)
XML-004   CDATA injection with script content (MEDIUM)
XML-005   Oversized XML payload (HIGH)
XML-006   XSLT injection (HIGH)
XML-007   Namespace poisoning via unexpected external URI (MEDIUM)

Usage::

    from shared.rulepacks.xml_security_pack import (
        XMLSecurityPack,
        XMLRequest,
    )

    pack = XMLSecurityPack(max_payload_kb=256)
    req  = XMLRequest(content="<?xml version='1.0'?><root/>")
    result = pack.evaluate(req)
    print(result.summary())
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Check weight registry
# ---------------------------------------------------------------------------

# Each check ID maps to its contribution toward the 0–100 risk score.
# The final score is: min(100, sum of weights for each *unique* fired ID).
_CHECK_WEIGHTS: Dict[str, int] = {
    "XML-001": 45,  # XXE via DOCTYPE ENTITY — CRITICAL
    "XML-002": 30,  # XML bomb / entity expansion — HIGH
    "XML-003": 30,  # DTD external resource reference — HIGH
    "XML-004": 15,  # CDATA script injection — MEDIUM
    "XML-005": 20,  # Oversized payload — HIGH
    "XML-006": 25,  # XSLT injection — HIGH
    "XML-007": 15,  # Namespace poisoning — MEDIUM
}


# ---------------------------------------------------------------------------
# Severity ordering helper (module-level, reused by pack)
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
    "INFO":     0,
}


def _severity_value(severity: str) -> int:
    """Map a severity label string to its integer ordinal."""
    return _SEVERITY_ORDER.get(severity.upper(), 0)


# ---------------------------------------------------------------------------
# Pre-compiled patterns
# ---------------------------------------------------------------------------

# XML-001: XXE detection patterns
# Pattern A: DOCTYPE with inline internal subset that also contains ENTITY
_XXE_DOCTYPE_INTERNAL_SUBSET_RE = re.compile(
    r'<!DOCTYPE\s+\w+\s*\[',
    re.IGNORECASE,
)
_XXE_ENTITY_DECL_RE = re.compile(
    r'<!ENTITY\s+\w+',
    re.IGNORECASE,
)
# Pattern B: DOCTYPE with SYSTEM keyword (external entity reference)
_XXE_DOCTYPE_SYSTEM_RE = re.compile(
    r'<!DOCTYPE\s+\w+\s+SYSTEM\s+',
    re.IGNORECASE,
)
# Pattern C: DOCTYPE with PUBLIC keyword
_XXE_DOCTYPE_PUBLIC_RE = re.compile(
    r'<!DOCTYPE\s+\w+\s+PUBLIC\s+',
    re.IGNORECASE,
)

# XML-002: XML bomb detection
# Count all ENTITY declarations to find bombs with many expansions
_ENTITY_ALL_RE = re.compile(r'<!ENTITY\s', re.IGNORECASE)
# Nested entity reference: an entity whose value itself references another entity
_ENTITY_NESTED_DOUBLE_RE = re.compile(
    r'<!ENTITY\s+\w+\s+"[^"]*&\w+;[^"]*"',
    re.IGNORECASE,
)
_ENTITY_NESTED_SINGLE_RE = re.compile(
    r"<!ENTITY\s+\w+\s+'[^']*&\w+;[^']*'",
    re.IGNORECASE,
)

# XML-003: DTD external resource references
_DTD_SYSTEM_URI_RE = re.compile(
    r'SYSTEM\s+"(?:file://|http://|https://|ftp://|//)',
    re.IGNORECASE,
)
_DTD_SYSTEM_URI_SINGLE_RE = re.compile(
    r"SYSTEM\s+'(?:file://|http://|https://|ftp://|//)",
    re.IGNORECASE,
)
_DTD_ENTITY_SYSTEM_RE = re.compile(
    r'<!ENTITY\s+\w+\s+SYSTEM\s+',
    re.IGNORECASE,
)

# XML-004: CDATA injection with script content
_CDATA_SCRIPT_RE = re.compile(
    r'<!\[CDATA\[.*?(?:script|javascript:|document\.|eval\(|onload=).*?\]\]>',
    re.IGNORECASE | re.DOTALL,
)

# XML-006: XSLT injection
_XSLT_RE = re.compile(
    r'<xsl:(value-of|for-each|include|import)\b',
    re.IGNORECASE,
)

# XML-007: Namespace URI extraction
_XMLNS_URI_RE = re.compile(
    r'xmlns:\w+\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# Safe namespace URI prefixes that are permitted and will NOT trigger XML-007
_SAFE_NAMESPACE_PREFIXES = (
    "http://www.w3.org/",
    "http://schemas.xmlsoap.org/",
    "http://www.openformats.org/",
    "urn:",
    "http://purl.org/",
)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class XMLRequest:
    """
    Represents a single inbound XML payload to be evaluated.

    Attributes:
        content:      Raw XML string to be analysed.
        content_type: MIME type of the request body (default ``application/xml``).
        source_ip:    Originating client IP address for logging purposes.
        endpoint:     API endpoint or URL path that received the payload.
    """
    content:      str
    content_type: str = "application/xml"
    source_ip:    Optional[str] = None
    endpoint:     Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dictionary suitable for JSON output."""
        return {
            "content":      self.content,
            "content_type": self.content_type,
            "source_ip":    self.source_ip,
            "endpoint":     self.endpoint,
        }


@dataclass
class XMLFinding:
    """
    Represents a single security finding raised against an XML request.

    Attributes:
        check_id:       Rule identifier (e.g. ``XML-001``).
        severity:       Severity label: CRITICAL, HIGH, MEDIUM, LOW, or INFO.
        rule_name:      Short human-readable rule name.
        evidence:       First 100 characters of the matched region for triage.
        recommendation: Remediation guidance.
    """
    check_id:       str
    severity:       str
    rule_name:      str
    evidence:       str  # first 100 chars of the matched/triggering region
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dictionary suitable for JSON output."""
        return {
            "check_id":       self.check_id,
            "severity":       self.severity,
            "rule_name":      self.rule_name,
            "evidence":       self.evidence,
            "recommendation": self.recommendation,
        }


@dataclass
class XMLEvalResult:
    """
    Aggregated evaluation result for a single XML request.

    Attributes:
        findings:          Ordered list of XMLFinding objects (may be empty).
        risk_score:        Integer 0–100 representing cumulative risk.
        blocked:           True if at least one finding meets or exceeds the
                           configured block_on_severity threshold.
        block_on_severity: The severity threshold used when computing blocked.
    """
    findings:          List[XMLFinding]
    risk_score:        int
    blocked:           bool
    block_on_severity: str = "HIGH"

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """One-line human-readable summary of the evaluation result."""
        status = "BLOCKED" if self.blocked else "ALLOWED"
        n = len(self.findings)
        finding_word = "finding" if n == 1 else "findings"
        if self.findings:
            ids = ", ".join(f.check_id for f in self.findings)
            return (
                f"XML eval [{status}] | risk_score={self.risk_score} | "
                f"{n} {finding_word}: {ids}"
            )
        return (
            f"XML eval [{status}] | risk_score={self.risk_score} | 0 findings"
        )

    def by_severity(self) -> Dict[str, List[XMLFinding]]:
        """
        Group findings by severity label.

        Returns a dict with keys for every known severity level; each value
        is a (possibly empty) list of XMLFinding objects.
        """
        result: Dict[str, List[XMLFinding]] = {
            "CRITICAL": [],
            "HIGH":     [],
            "MEDIUM":   [],
            "LOW":      [],
            "INFO":     [],
        }
        for finding in self.findings:
            bucket = result.get(finding.severity)
            if bucket is not None:
                bucket.append(finding)
            else:
                # Unknown severity — add a dynamic bucket rather than discard
                result[finding.severity] = [finding]
        return result

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the full result to a plain dictionary."""
        return {
            "findings":          [f.to_dict() for f in self.findings],
            "risk_score":        self.risk_score,
            "blocked":           self.blocked,
            "block_on_severity": self.block_on_severity,
        }


# ---------------------------------------------------------------------------
# XMLSecurityPack
# ---------------------------------------------------------------------------

class XMLSecurityPack:
    """
    WAF security rulepack for XML-specific attack pattern detection.

    The pack runs seven deterministic, regex-only checks against each
    XMLRequest and aggregates the results into an XMLEvalResult.  No external
    XML parsing library is required; all analysis is performed on the raw
    string content.

    Args:
        max_payload_kb:    Maximum allowed payload size in kilobytes before
                           XML-005 fires (default ``512``).
        block_on_severity: Minimum finding severity that causes blocked=True
                           (default ``"HIGH"``).

    Example::

        pack   = XMLSecurityPack(max_payload_kb=128, block_on_severity="MEDIUM")
        result = pack.evaluate(XMLRequest(content="<root/>"))
        if result.blocked:
            raise PermissionError(result.summary())
    """

    def __init__(
        self,
        max_payload_kb:    int = 512,
        block_on_severity: str = "HIGH",
    ) -> None:
        self._max_payload_kb    = max_payload_kb
        self._block_on_severity = block_on_severity

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def evaluate(self, request: XMLRequest) -> XMLEvalResult:
        """
        Evaluate a single XMLRequest against all seven security checks.

        Returns an XMLEvalResult with findings, risk_score, and blocked flag.
        """
        findings: List[XMLFinding] = []

        # Run all checks; each returns either an XMLFinding or None
        for check_fn in (
            self._check_xml_001_xxe,
            self._check_xml_002_xml_bomb,
            self._check_xml_003_dtd_external,
            self._check_xml_004_cdata_script,
            self._check_xml_005_oversized,
            self._check_xml_006_xslt,
            self._check_xml_007_namespace_poison,
        ):
            finding = check_fn(request)
            if finding is not None:
                findings.append(finding)

        # risk_score = min(100, sum of weights for unique fired check IDs)
        fired_ids = {f.check_id for f in findings}
        risk_score = min(100, sum(_CHECK_WEIGHTS.get(cid, 0) for cid in fired_ids))

        # Determine blocked status based on configured severity threshold
        threshold = _severity_value(self._block_on_severity)
        blocked = any(
            _severity_value(f.severity) >= threshold for f in findings
        )

        return XMLEvalResult(
            findings=findings,
            risk_score=risk_score,
            blocked=blocked,
            block_on_severity=self._block_on_severity,
        )

    def evaluate_many(
        self,
        requests: List[XMLRequest],
    ) -> List[XMLEvalResult]:
        """
        Evaluate a batch of XMLRequest objects.

        Returns a list of XMLEvalResult in the same order as the input.
        """
        return [self.evaluate(req) for req in requests]

    # ------------------------------------------------------------------
    # Individual check implementations
    # ------------------------------------------------------------------

    def _check_xml_001_xxe(
        self,
        request: XMLRequest,
    ) -> Optional[XMLFinding]:
        """
        XML-001: XXE via DOCTYPE with ENTITY declaration (CRITICAL, weight 45).

        Fires when the content:
        - Contains a DOCTYPE with an internal subset ``[`` AND at least one
          ``<!ENTITY`` declaration inside it, OR
        - Contains ``<!DOCTYPE ... SYSTEM `` (external SYSTEM entity), OR
        - Contains ``<!DOCTYPE ... PUBLIC `` (external PUBLIC entity).
        """
        content = request.content

        # Condition A: internal subset DOCTYPE combined with at least one ENTITY
        if (
            _XXE_DOCTYPE_INTERNAL_SUBSET_RE.search(content)
            and _XXE_ENTITY_DECL_RE.search(content)
        ):
            # Capture the DOCTYPE token as evidence
            m = _XXE_DOCTYPE_INTERNAL_SUBSET_RE.search(content)
            evidence = m.group(0)[:100] if m else content[:100]
            return XMLFinding(
                check_id="XML-001",
                severity="CRITICAL",
                rule_name="XXE via DOCTYPE Internal Subset",
                evidence=evidence,
                recommendation=(
                    "Disable DOCTYPE declarations and external entity processing "
                    "in your XML parser.  Use a hardened parser such as defusedxml "
                    "or configure lxml with resolve_entities=False."
                ),
            )

        # Condition B: external SYSTEM entity
        m_sys = _XXE_DOCTYPE_SYSTEM_RE.search(content)
        if m_sys:
            evidence = m_sys.group(0)[:100]
            return XMLFinding(
                check_id="XML-001",
                severity="CRITICAL",
                rule_name="XXE via DOCTYPE SYSTEM Entity",
                evidence=evidence,
                recommendation=(
                    "Disable DOCTYPE declarations and SYSTEM entity resolution. "
                    "Reject any XML document containing a DOCTYPE declaration at "
                    "the gateway before it reaches the application parser."
                ),
            )

        # Condition C: PUBLIC entity
        m_pub = _XXE_DOCTYPE_PUBLIC_RE.search(content)
        if m_pub:
            evidence = m_pub.group(0)[:100]
            return XMLFinding(
                check_id="XML-001",
                severity="CRITICAL",
                rule_name="XXE via DOCTYPE PUBLIC Entity",
                evidence=evidence,
                recommendation=(
                    "Disable DOCTYPE declarations and PUBLIC entity resolution. "
                    "Reject any XML document containing a DOCTYPE declaration at "
                    "the gateway before it reaches the application parser."
                ),
            )

        return None

    def _check_xml_002_xml_bomb(
        self,
        request: XMLRequest,
    ) -> Optional[XMLFinding]:
        """
        XML-002: XML bomb / exponential entity expansion (HIGH, weight 30).

        Fires when:
        - More than 5 ``<!ENTITY`` declarations appear in the document (a
          classic "billion laughs" setup), OR
        - Any ENTITY declaration value itself references another entity
          (``&name;`` inside the declaration value), indicating recursive
          or chained expansion.
        """
        content = request.content

        # Condition A: more than 5 entity declarations
        entity_matches = _ENTITY_ALL_RE.findall(content)
        if len(entity_matches) > 5:
            evidence = f"Found {len(entity_matches)} <!ENTITY declarations"[:100]
            return XMLFinding(
                check_id="XML-002",
                severity="HIGH",
                rule_name="XML Bomb: Excessive Entity Declarations",
                evidence=evidence,
                recommendation=(
                    "Limit the number of entity declarations accepted per document. "
                    "Disable entity expansion entirely in production XML parsers and "
                    "reject documents with more than a safe threshold of entity definitions."
                ),
            )

        # Condition B: nested/chained entity reference in a declaration value
        m_nested = _ENTITY_NESTED_DOUBLE_RE.search(content)
        if m_nested is None:
            m_nested = _ENTITY_NESTED_SINGLE_RE.search(content)

        if m_nested:
            evidence = m_nested.group(0)[:100]
            return XMLFinding(
                check_id="XML-002",
                severity="HIGH",
                rule_name="XML Bomb: Nested Entity Reference",
                evidence=evidence,
                recommendation=(
                    "Disallow entity declarations whose values reference other "
                    "entities.  This recursive expansion pattern is the mechanism "
                    "behind 'billion laughs' and related XML DoS attacks."
                ),
            )

        return None

    def _check_xml_003_dtd_external(
        self,
        request: XMLRequest,
    ) -> Optional[XMLFinding]:
        """
        XML-003: DTD external resource reference (HIGH, weight 30).

        Fires when:
        - A SYSTEM keyword is followed by a URI scheme associated with external
          resource loading (``file://``, ``http://``, ``https://``, ``ftp://``,
          or protocol-relative ``//``), OR
        - An ``<!ENTITY ... SYSTEM`` declaration is present, indicating a named
          external entity regardless of URI scheme.
        """
        content = request.content

        # Condition A: SYSTEM URI with dangerous scheme (double-quoted)
        m = _DTD_SYSTEM_URI_RE.search(content)
        if m is None:
            # Try single-quoted variant
            m = _DTD_SYSTEM_URI_SINGLE_RE.search(content)

        if m:
            evidence = m.group(0)[:100]
            return XMLFinding(
                check_id="XML-003",
                severity="HIGH",
                rule_name="DTD External Resource via SYSTEM URI",
                evidence=evidence,
                recommendation=(
                    "Block all XML documents containing SYSTEM or PUBLIC entity "
                    "references that point to external URIs.  Configure the XML "
                    "parser to forbid external entity resolution and DTD loading."
                ),
            )

        # Condition B: any named SYSTEM entity declaration
        m_ent = _DTD_ENTITY_SYSTEM_RE.search(content)
        if m_ent:
            evidence = m_ent.group(0)[:100]
            return XMLFinding(
                check_id="XML-003",
                severity="HIGH",
                rule_name="DTD External Entity Declaration",
                evidence=evidence,
                recommendation=(
                    "Reject XML documents that declare SYSTEM entities.  External "
                    "entity declarations allow the parser to fetch arbitrary resources "
                    "from the filesystem or network on the server's behalf."
                ),
            )

        return None

    def _check_xml_004_cdata_script(
        self,
        request: XMLRequest,
    ) -> Optional[XMLFinding]:
        """
        XML-004: CDATA injection with script content (MEDIUM, weight 15).

        Fires when a ``<![CDATA[...]]>`` section contains script-like content:
        ``<script``, ``javascript:``, ``document.``, ``eval(``, or ``onload=``.
        The DOTALL flag is set so the match spans newlines.
        """
        content = request.content

        m = _CDATA_SCRIPT_RE.search(content)
        if m:
            evidence = m.group(0)[:100]
            return XMLFinding(
                check_id="XML-004",
                severity="MEDIUM",
                rule_name="CDATA Script Injection",
                evidence=evidence,
                recommendation=(
                    "Strip or reject CDATA sections whose content includes script "
                    "keywords before the payload is rendered in any browser or "
                    "HTML-processing context.  Apply output encoding when embedding "
                    "XML data in HTML responses."
                ),
            )

        return None

    def _check_xml_005_oversized(
        self,
        request: XMLRequest,
    ) -> Optional[XMLFinding]:
        """
        XML-005: Oversized XML payload (HIGH, weight 20).

        Fires when the UTF-8 byte length of the content exceeds
        ``max_payload_kb * 1024`` bytes.  Large payloads can trigger
        parser DoS or memory exhaustion.
        """
        byte_length = len(request.content.encode("utf-8"))
        limit_bytes = self._max_payload_kb * 1024

        if byte_length > limit_bytes:
            evidence = (
                f"Payload size {byte_length} bytes exceeds limit "
                f"{limit_bytes} bytes ({self._max_payload_kb} KB)"
            )[:100]
            return XMLFinding(
                check_id="XML-005",
                severity="HIGH",
                rule_name="Oversized XML Payload",
                evidence=evidence,
                recommendation=(
                    "Enforce a maximum request body size at the reverse proxy or "
                    "load balancer before the payload reaches the application tier. "
                    f"Reject XML documents larger than {self._max_payload_kb} KB."
                ),
            )

        return None

    def _check_xml_006_xslt(
        self,
        request: XMLRequest,
    ) -> Optional[XMLFinding]:
        """
        XML-006: XSLT injection (HIGH, weight 25).

        Fires when the content contains XSL transform directives:
        ``<xsl:value-of``, ``<xsl:for-each``, ``<xsl:include``, or
        ``<xsl:import``.  These elements can load external resources or
        execute arbitrary expressions when processed by an XSLT engine.
        """
        content = request.content

        m = _XSLT_RE.search(content)
        if m:
            evidence = m.group(0)[:100]
            return XMLFinding(
                check_id="XML-006",
                severity="HIGH",
                rule_name="XSLT Injection",
                evidence=evidence,
                recommendation=(
                    "Reject XML payloads containing XSL transform directives unless "
                    "XSLT processing is an explicit and authenticated use case. "
                    "If XSLT must be supported, restrict the XPath expressions and "
                    "disable xsl:include and xsl:import to prevent remote resource loading."
                ),
            )

        return None

    def _check_xml_007_namespace_poison(
        self,
        request: XMLRequest,
    ) -> Optional[XMLFinding]:
        """
        XML-007: Namespace poisoning via unexpected external URI (MEDIUM, weight 15).

        Extracts all ``xmlns:prefix="..."`` declarations and fires when any
        URI does not start with a known-safe prefix:
        ``http://www.w3.org/``, ``http://schemas.xmlsoap.org/``,
        ``http://www.openformats.org/``, ``urn:``, or ``http://purl.org/``.

        Only URIs containing ``file://``, ``http://``, or ``https://`` are
        flagged — bare non-URI namespace tokens are ignored.
        """
        content = request.content

        uris = _XMLNS_URI_RE.findall(content)
        for uri in uris:
            uri_lower = uri.lower()

            # Only examine URIs with a network/file scheme
            if not (
                uri_lower.startswith("file://")
                or uri_lower.startswith("http://")
                or uri_lower.startswith("https://")
            ):
                continue

            # Allow well-known safe namespace base URIs
            if any(uri_lower.startswith(safe) for safe in _SAFE_NAMESPACE_PREFIXES):
                continue

            # URI is external and not on the safe list — potential namespace poisoning
            evidence = f'xmlns declaration with unsafe URI: {uri}'[:100]
            return XMLFinding(
                check_id="XML-007",
                severity="MEDIUM",
                rule_name="Namespace Poisoning",
                evidence=evidence,
                recommendation=(
                    "Validate all XML namespace URIs against an allow-list of known-safe "
                    "prefixes.  Reject documents that declare namespaces pointing to "
                    "external or unexpected URIs, as they may be used to confuse schema "
                    "validators or trigger unexpected parser behaviour."
                ),
            )

        return None
