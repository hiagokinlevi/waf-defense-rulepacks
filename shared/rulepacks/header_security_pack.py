#!/usr/bin/env python3
"""
HTTP Security Header Analyzer
================================
Analyzes HTTP response headers for missing or misconfigured security
controls: HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, Permissions-Policy, and sensitive header leakage.

Operates on header dicts (case-insensitive matching).

Check IDs
----------
HDR-001   Missing Strict-Transport-Security (HSTS)
HDR-002   HSTS max-age too short (< 31536000 seconds / 1 year)
HDR-003   Missing Content-Security-Policy
HDR-004   Missing X-Frame-Options (clickjacking protection)
HDR-005   Missing X-Content-Type-Options: nosniff
HDR-006   Missing Referrer-Policy
HDR-007   Server header leaks version information
HDR-008   X-Powered-By header present (technology disclosure)
HDR-009   Missing Permissions-Policy (Feature-Policy)
HDR-010   CSP contains 'unsafe-inline' or 'unsafe-eval'

Usage::

    from shared.rulepacks.header_security_pack import HeaderSecurityPack, HeaderRequest

    headers = {
        "Content-Type": "text/html",
        "Server": "Apache/2.4.52 (Ubuntu)",
        "X-Powered-By": "PHP/8.1.0",
    }
    pack = HeaderSecurityPack()
    result = pack.evaluate(headers)
    for match in result.matches:
        print(match.to_dict())
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

class HeaderSeverity(Enum):
    """Severity levels for header security findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# ---------------------------------------------------------------------------
# Rule weight registry
# ---------------------------------------------------------------------------

# Maps rule_id → integer weight used to accumulate a risk score (0-100).
_RULE_WEIGHTS: Dict[str, int] = {
    "HDR-001": 35,
    "HDR-002": 20,
    "HDR-003": 30,
    "HDR-004": 25,
    "HDR-005": 20,
    "HDR-006": 15,
    "HDR-007": 20,
    "HDR-008": 15,
    "HDR-009": 10,
    "HDR-010": 30,
}


# ---------------------------------------------------------------------------
# HeaderMatch
# ---------------------------------------------------------------------------

@dataclass
class HeaderMatch:
    """A single finding produced by the header security analyzer."""

    rule_id: str
    severity: HeaderSeverity
    title: str
    detail: str
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> Dict:
        """Return a plain-dict representation suitable for JSON serialization."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }

    def summary(self) -> str:
        """Return a one-line human-readable summary of this match."""
        return f"[{self.severity.value}] {self.rule_id}: {self.title}"


# ---------------------------------------------------------------------------
# HeaderResult
# ---------------------------------------------------------------------------

@dataclass
class HeaderResult:
    """Aggregated result of a single header evaluation run."""

    matches: List[HeaderMatch] = field(default_factory=list)
    risk_score: int = 0
    headers_analyzed: int = 0
    generated_at: float = field(default_factory=time.time)

    # ------------------------------------------------------------------
    # Computed properties
    # ------------------------------------------------------------------

    @property
    def total_matches(self) -> int:
        """Total number of findings."""
        return len(self.matches)

    @property
    def critical_matches(self) -> List[HeaderMatch]:
        """All findings with CRITICAL severity."""
        return [m for m in self.matches if m.severity == HeaderSeverity.CRITICAL]

    @property
    def high_matches(self) -> List[HeaderMatch]:
        """All findings with HIGH severity."""
        return [m for m in self.matches if m.severity == HeaderSeverity.HIGH]

    def matches_by_rule(self, rule_id: str) -> List[HeaderMatch]:
        """Return all findings for a specific rule ID."""
        return [m for m in self.matches if m.rule_id == rule_id]

    def summary(self) -> str:
        """Return a brief human-readable summary of this result."""
        return (
            f"HeaderResult: {self.total_matches} finding(s), "
            f"risk_score={self.risk_score}"
        )

    def to_dict(self) -> Dict:
        """Return a full dict representation of this result."""
        return {
            "risk_score": self.risk_score,
            "total_matches": self.total_matches,
            "headers_analyzed": self.headers_analyzed,
            "generated_at": self.generated_at,
            "matches": [m.to_dict() for m in self.matches],
        }


# ---------------------------------------------------------------------------
# HeaderSecurityPack
# ---------------------------------------------------------------------------

class HeaderSecurityPack:
    """
    Evaluates HTTP response headers against a set of security rules.

    Parameters
    ----------
    require_hsts : bool
        When True (default) HDR-001 fires if HSTS is absent.
    require_csp : bool
        When True (default) HDR-003 fires if CSP is absent.
    require_permissions_policy : bool
        When True (default) HDR-009 fires if Permissions-Policy (or the
        legacy Feature-Policy) is absent.
    min_hsts_age : int
        Minimum acceptable HSTS max-age in seconds.  Default is 31536000
        (one year).  HDR-002 fires if the observed value is strictly less
        than this.
    """

    def __init__(
        self,
        require_hsts: bool = True,
        require_csp: bool = True,
        require_permissions_policy: bool = True,
        min_hsts_age: int = 31536000,
    ) -> None:
        self.require_hsts = require_hsts
        self.require_csp = require_csp
        self.require_permissions_policy = require_permissions_policy
        self.min_hsts_age = min_hsts_age

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, headers: Dict[str, str]) -> HeaderResult:
        """
        Analyse a single header dict and return a :class:`HeaderResult`.

        Header keys are matched case-insensitively: both "Server" and
        "SERVER" refer to the same header.

        Parameters
        ----------
        headers:
            Mapping of header name → header value.

        Returns
        -------
        HeaderResult
            Contains all fired :class:`HeaderMatch` instances plus an
            aggregated risk score (capped at 100).
        """
        # Normalise all keys to lowercase once so every check below can
        # use simple dict lookups instead of repeated case folding.
        norm: Dict[str, str] = {k.lower(): v for k, v in headers.items()}

        matches: List[HeaderMatch] = []
        fired_rule_ids: List[str] = []

        # Collect matches from each individual check.
        for check_fn in (
            self._check_hdr001,
            self._check_hdr002,
            self._check_hdr003,
            self._check_hdr004,
            self._check_hdr005,
            self._check_hdr006,
            self._check_hdr007,
            self._check_hdr008,
            self._check_hdr009,
            self._check_hdr010,
        ):
            result: Optional[HeaderMatch] = check_fn(norm)
            if result is not None:
                matches.append(result)
                fired_rule_ids.append(result.rule_id)

        # Risk score: sum weights for unique fired rules, cap at 100.
        unique_fired = set(fired_rule_ids)
        raw_score = sum(_RULE_WEIGHTS.get(rid, 0) for rid in unique_fired)
        risk_score = min(raw_score, 100)

        return HeaderResult(
            matches=matches,
            risk_score=risk_score,
            headers_analyzed=len(headers),
        )

    def evaluate_many(
        self, header_list: List[Dict[str, str]]
    ) -> List[HeaderResult]:
        """
        Batch-evaluate a list of header dicts.

        Parameters
        ----------
        header_list:
            Each element is passed to :meth:`evaluate` independently.

        Returns
        -------
        List[HeaderResult]
            One result per input dict, in the same order.
        """
        return [self.evaluate(h) for h in header_list]

    # ------------------------------------------------------------------
    # Individual checks (return HeaderMatch or None)
    # ------------------------------------------------------------------

    def _check_hdr001(self, norm: Dict[str, str]) -> Optional[HeaderMatch]:
        """HDR-001 — Missing Strict-Transport-Security."""
        if not self.require_hsts:
            return None
        if "strict-transport-security" in norm:
            return None
        return HeaderMatch(
            rule_id="HDR-001",
            severity=HeaderSeverity.HIGH,
            title="Missing Strict-Transport-Security (HSTS)",
            detail=(
                "The response does not include a Strict-Transport-Security "
                "header.  Without HSTS, browsers will not enforce HTTPS "
                "connections, leaving users vulnerable to protocol downgrade "
                "attacks and man-in-the-middle interception."
            ),
            evidence="Header 'Strict-Transport-Security' not present in response.",
            remediation=(
                "Add: Strict-Transport-Security: max-age=31536000; "
                "includeSubDomains; preload"
            ),
        )

    def _check_hdr002(self, norm: Dict[str, str]) -> Optional[HeaderMatch]:
        """HDR-002 — HSTS max-age too short."""
        hsts_value = norm.get("strict-transport-security")
        if hsts_value is None:
            # HDR-001 covers the missing-header case; nothing to do here.
            return None

        match = re.search(r"max-age=(\d+)", hsts_value, re.IGNORECASE)
        if not match:
            # Cannot parse max-age; treat as misconfigured.
            return HeaderMatch(
                rule_id="HDR-002",
                severity=HeaderSeverity.MEDIUM,
                title="HSTS max-age too short or unparseable",
                detail=(
                    "The Strict-Transport-Security header is present but its "
                    "max-age directive could not be parsed or is missing."
                ),
                evidence=f"Strict-Transport-Security: {hsts_value}",
                remediation=(
                    f"Set max-age to at least {self.min_hsts_age} seconds "
                    "(e.g. max-age=31536000)."
                ),
            )

        observed_age = int(match.group(1))
        if observed_age < self.min_hsts_age:
            return HeaderMatch(
                rule_id="HDR-002",
                severity=HeaderSeverity.MEDIUM,
                title="HSTS max-age too short",
                detail=(
                    f"The HSTS max-age directive is {observed_age} seconds, "
                    f"which is below the required minimum of "
                    f"{self.min_hsts_age} seconds ({self.min_hsts_age // 86400} days).  "
                    "A short max-age reduces the effectiveness of HSTS "
                    "because browsers will stop enforcing HTTPS sooner."
                ),
                evidence=f"Strict-Transport-Security: {hsts_value}",
                remediation=(
                    f"Increase max-age to at least {self.min_hsts_age}: "
                    f"Strict-Transport-Security: max-age={self.min_hsts_age}; "
                    "includeSubDomains"
                ),
            )
        return None

    def _check_hdr003(self, norm: Dict[str, str]) -> Optional[HeaderMatch]:
        """HDR-003 — Missing Content-Security-Policy."""
        if not self.require_csp:
            return None
        if "content-security-policy" in norm:
            return None
        return HeaderMatch(
            rule_id="HDR-003",
            severity=HeaderSeverity.HIGH,
            title="Missing Content-Security-Policy",
            detail=(
                "The response does not include a Content-Security-Policy "
                "header.  Without CSP, the browser applies no restrictions "
                "on which resources the page may load, significantly "
                "increasing the attack surface for XSS and data injection."
            ),
            evidence="Header 'Content-Security-Policy' not present in response.",
            remediation=(
                "Add a Content-Security-Policy header with a strict policy, "
                "e.g.: Content-Security-Policy: default-src 'self'"
            ),
        )

    def _check_hdr004(self, norm: Dict[str, str]) -> Optional[HeaderMatch]:
        """HDR-004 — Missing X-Frame-Options."""
        if "x-frame-options" in norm:
            return None
        return HeaderMatch(
            rule_id="HDR-004",
            severity=HeaderSeverity.MEDIUM,
            title="Missing X-Frame-Options (clickjacking protection)",
            detail=(
                "The response does not include an X-Frame-Options header.  "
                "Without this header, the page may be embedded inside an "
                "<iframe> on a malicious site, enabling clickjacking attacks "
                "that trick users into clicking hidden UI elements."
            ),
            evidence="Header 'X-Frame-Options' not present in response.",
            remediation=(
                "Add: X-Frame-Options: DENY  (or SAMEORIGIN if same-origin "
                "framing is required).  Alternatively, use "
                "Content-Security-Policy: frame-ancestors 'none'."
            ),
        )

    def _check_hdr005(self, norm: Dict[str, str]) -> Optional[HeaderMatch]:
        """HDR-005 — Missing or wrong X-Content-Type-Options."""
        value = norm.get("x-content-type-options")
        if value is not None and value.strip().lower() == "nosniff":
            return None
        if value is None:
            evidence = "Header 'X-Content-Type-Options' not present in response."
            detail = (
                "The response does not include an X-Content-Type-Options "
                "header.  Without 'nosniff', browsers may MIME-sniff "
                "responses and interpret them as a different content type, "
                "enabling certain XSS vectors."
            )
        else:
            evidence = f"X-Content-Type-Options: {value}"
            detail = (
                f"The X-Content-Type-Options header is set to '{value}' "
                "instead of the required value 'nosniff'.  Only 'nosniff' "
                "instructs browsers to block MIME-type sniffing."
            )
        return HeaderMatch(
            rule_id="HDR-005",
            severity=HeaderSeverity.MEDIUM,
            title="Missing or misconfigured X-Content-Type-Options",
            detail=detail,
            evidence=evidence,
            remediation="Add: X-Content-Type-Options: nosniff",
        )

    def _check_hdr006(self, norm: Dict[str, str]) -> Optional[HeaderMatch]:
        """HDR-006 — Missing Referrer-Policy."""
        if "referrer-policy" in norm:
            return None
        return HeaderMatch(
            rule_id="HDR-006",
            severity=HeaderSeverity.LOW,
            title="Missing Referrer-Policy",
            detail=(
                "The response does not include a Referrer-Policy header.  "
                "Without an explicit policy, browsers may send the full "
                "URL in the Referer header to third parties, potentially "
                "leaking sensitive path or query-string information."
            ),
            evidence="Header 'Referrer-Policy' not present in response.",
            remediation=(
                "Add: Referrer-Policy: strict-origin-when-cross-origin  "
                "(or a stricter policy such as 'no-referrer')."
            ),
        )

    def _check_hdr007(self, norm: Dict[str, str]) -> Optional[HeaderMatch]:
        """HDR-007 — Server header leaks version information."""
        server_value = norm.get("server")
        if server_value is None:
            return None

        # Flag when the header contains a slash followed by digits/dots
        # (e.g. "Apache/2.4.52") OR standalone version tokens like "2.4.52".
        version_pattern = re.compile(r"[\d.]+")
        if not version_pattern.search(server_value):
            # No version-like digits found; header is safe.
            return None

        return HeaderMatch(
            rule_id="HDR-007",
            severity=HeaderSeverity.MEDIUM,
            title="Server header leaks version information",
            detail=(
                "The Server response header discloses software version "
                "information.  Attackers can use this to identify specific "
                "vulnerable versions and target known CVEs without needing "
                "active enumeration."
            ),
            evidence=f"Server: {server_value}",
            remediation=(
                "Configure the server to suppress version details from the "
                "Server header (e.g., 'ServerTokens Prod' in Apache, "
                "'server_tokens off' in nginx).  Ideally remove the header "
                "entirely or set it to a generic value such as 'Server: web'."
            ),
        )

    def _check_hdr008(self, norm: Dict[str, str]) -> Optional[HeaderMatch]:
        """HDR-008 — X-Powered-By header present."""
        value = norm.get("x-powered-by")
        if value is None:
            return None
        return HeaderMatch(
            rule_id="HDR-008",
            severity=HeaderSeverity.LOW,
            title="X-Powered-By header present (technology disclosure)",
            detail=(
                "The X-Powered-By response header discloses the underlying "
                "technology stack (e.g., PHP version, ASP.NET version).  "
                "This information assists attackers in identifying targets "
                "for known vulnerabilities."
            ),
            evidence=f"X-Powered-By: {value}",
            remediation=(
                "Remove the X-Powered-By header entirely.  In PHP: "
                "'expose_php = Off' in php.ini.  In Express.js: "
                "app.disable('x-powered-by') or use the helmet middleware."
            ),
        )

    def _check_hdr009(self, norm: Dict[str, str]) -> Optional[HeaderMatch]:
        """HDR-009 — Missing Permissions-Policy (Feature-Policy)."""
        if not self.require_permissions_policy:
            return None
        # Accept either the modern 'permissions-policy' or the legacy
        # 'feature-policy' header.
        if "permissions-policy" in norm or "feature-policy" in norm:
            return None
        return HeaderMatch(
            rule_id="HDR-009",
            severity=HeaderSeverity.LOW,
            title="Missing Permissions-Policy",
            detail=(
                "The response does not include a Permissions-Policy header "
                "(formerly Feature-Policy).  Without this header, the page "
                "grants the browser's default access to powerful features "
                "such as camera, microphone, and geolocation, which may be "
                "abused by third-party scripts."
            ),
            evidence=(
                "Neither 'Permissions-Policy' nor 'Feature-Policy' present "
                "in response."
            ),
            remediation=(
                "Add: Permissions-Policy: geolocation=(), microphone=(), "
                "camera=()  (adjust feature list to your application's "
                "actual requirements)."
            ),
        )

    def _check_hdr010(self, norm: Dict[str, str]) -> Optional[HeaderMatch]:
        """HDR-010 — CSP contains 'unsafe-inline' or 'unsafe-eval'."""
        csp_value = norm.get("content-security-policy")
        if csp_value is None:
            # HDR-003 covers the missing-header case.
            return None

        csp_lower = csp_value.lower()
        found_directives: List[str] = []
        if "'unsafe-inline'" in csp_lower:
            found_directives.append("'unsafe-inline'")
        if "'unsafe-eval'" in csp_lower:
            found_directives.append("'unsafe-eval'")

        if not found_directives:
            return None

        joined = " and ".join(found_directives)
        return HeaderMatch(
            rule_id="HDR-010",
            severity=HeaderSeverity.HIGH,
            title="CSP contains unsafe directives",
            detail=(
                f"The Content-Security-Policy header contains {joined}.  "
                "These directives significantly weaken the policy: "
                "'unsafe-inline' allows arbitrary inline scripts and styles, "
                "and 'unsafe-eval' permits dynamic code execution via eval() "
                "and similar constructs, both of which are primary XSS "
                "exploitation vectors."
            ),
            evidence=f"Content-Security-Policy: {csp_value}",
            remediation=(
                "Remove 'unsafe-inline' and 'unsafe-eval' from your CSP.  "
                "Use nonces (nonce-<base64>) or hashes for legitimate inline "
                "scripts, and refactor code that relies on eval()."
            ),
        )
