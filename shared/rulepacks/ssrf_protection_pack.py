# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) 2026 Hiago Kin Levi
# Licensed under the Creative Commons Attribution 4.0 International License.
# https://creativecommons.org/licenses/by/4.0/
"""
SSRF Protection Rulepack
=========================
WAF rulepack that detects Server-Side Request Forgery (SSRF) attack patterns
in HTTP request parameters, body, and headers.  All analysis is performed
locally with compiled regular expressions — no live network requests are made.

Rule Catalogue
--------------
SSRF-001  RFC 1918 private IPv4 address in request values        (CRITICAL)
SSRF-002  Localhost / loopback reference                         (CRITICAL)
SSRF-003  Cloud metadata endpoint address                        (CRITICAL)
SSRF-004  DNS rebinding indicator (nip.io / xip.io / sslip.io …)(HIGH)
SSRF-005  Non-HTTP/HTTPS URL scheme (file://, gopher://, …)     (HIGH)
SSRF-006  URL shortener / redirect service abuse                 (MEDIUM)
SSRF-007  Internal service hostname pattern                      (HIGH)

Usage::

    from shared.rulepacks.ssrf_protection_pack import (
        HTTPRequest,
        SSRFProtectionPack,
    )

    pack = SSRFProtectionPack(block_on_severity="HIGH")
    result = pack.evaluate(
        HTTPRequest(
            url="https://example.com/fetch",
            query_params={"url": "http://169.254.169.254/latest/meta-data/"},
        )
    )
    print(result.summary())
    print(result.risk_score)       # -> 45
    print(result.blocked)          # -> True
"""
from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Severity ordering (used for block threshold comparison)
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
    "INFO":     0,
}


# ---------------------------------------------------------------------------
# Check weights  (risk_score = min(100, sum of weights for unique fired IDs)
# ---------------------------------------------------------------------------

_CHECK_WEIGHTS: Dict[str, int] = {
    "SSRF-001": 45,  # RFC 1918 private IP
    "SSRF-002": 45,  # Localhost / loopback
    "SSRF-003": 45,  # Cloud metadata endpoint
    "SSRF-004": 30,  # DNS rebinding indicator
    "SSRF-005": 30,  # Dangerous URL scheme
    "SSRF-006": 15,  # URL shortener abuse
    "SSRF-007": 25,  # Internal service hostname
}

_PRIVATE_IP_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

_METADATA_IPS = (
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("169.254.170.2"),
    ipaddress.ip_address("fd00:ec2::254"),
)


# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# SSRF-001 — RFC 1918 private IPv4 ranges
_PRIVATE_IP_PATTERNS: List[re.Pattern] = [
    re.compile(r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
    re.compile(r'172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'),
    re.compile(r'192\.168\.\d{1,3}\.\d{1,3}'),
]

# SSRF-002 — Localhost / loopback
# Use \b word-boundary so "notlocalhost.example.com" does NOT fire, while
# "localhost", "http://localhost/", etc. correctly do.
_LOOPBACK_PATTERNS: List[re.Pattern] = [
    re.compile(r'\blocalhost\b', re.IGNORECASE),
    re.compile(r'127\.0\.0\.\d+'),
    re.compile(r'::1'),
    re.compile(r'0\.0\.0\.0'),
]

# SSRF-003 — Cloud metadata endpoints
_METADATA_PATTERNS: List[re.Pattern] = [
    re.compile(r'169\.254\.169\.254'),       # AWS / GCP / Azure IMDS
    re.compile(r'metadata\.google\.internal', re.IGNORECASE),  # GCP internal DNS
    re.compile(r'169\.254\.170\.2'),          # AWS ECS credentials endpoint
    re.compile(r'fd00:ec2::254'),             # AWS IPv6 metadata
]

# SSRF-004 — DNS rebinding / IP-embedding domains
_DNS_REBIND_SUFFIXES_RE = re.compile(
    r'(^|[\w.-]+)\.'
    r'(nip\.io|xip\.io|sslip\.io|traefik\.me|localtest\.me|lvh\.me)'
    r'(/|$|:|\?)',
    re.IGNORECASE,
)
# Also catch bare IP-embedding patterns like 10-0-0-1.nip.io without path
_DNS_REBIND_BARE_RE = re.compile(
    r'[\w.-]+\.'
    r'(nip\.io|xip\.io|sslip\.io|traefik\.me|localtest\.me|lvh\.me)',
    re.IGNORECASE,
)

# SSRF-005 — Dangerous URL schemes
_DANGEROUS_SCHEMES: frozenset = frozenset([
    "file", "ftp", "gopher", "dict", "sftp", "ldap", "tftp", "smtp",
    "jar", "netdoc", "mailto", "imap",
])
_SCHEME_RE = re.compile(r'(\w+)://')

# SSRF-006 — Known URL shortener domains
_SHORTENER_DOMAINS: frozenset = frozenset([
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "tiny.cc",
])

# SSRF-007 — Internal service hostnames / TLD patterns
_INTERNAL_TLD_RE = re.compile(
    r'[\w-]+\.(internal|local|corp|intranet|lan|home|localdomain)'
    r'(/|$|:|\?|#)',
    re.IGNORECASE,
)
_INTERNAL_SERVICE_RE = re.compile(
    r'(^|[:/\\.@])'
    r'(redis|memcached|rabbitmq|kafka|elasticsearch|mongodb|mysql|'
    r'postgres|consul|vault|etcd|zookeeper|minio)'
    r'([:/\\.@$]|$)',
    re.IGNORECASE,
)


def _split_host_port(value: str) -> str:
    candidate = value.strip().strip("\"'")
    if "://" in candidate:
        try:
            parsed = urllib.parse.urlparse(candidate)
        except ValueError:
            parsed = None
        if parsed is not None and parsed.hostname:
            return parsed.hostname
    if candidate.startswith("[") and "]" in candidate:
        return candidate[1:candidate.index("]")]
    if candidate.count(":") == 1 and candidate.rsplit(":", 1)[1].isdigit():
        candidate = candidate.rsplit(":", 1)[0]
    for separator in ("/", "?", "#"):
        candidate = candidate.split(separator, 1)[0]
    return candidate


def _parse_ipv4_part(value: str) -> Optional[int]:
    if not value:
        return None
    if value.lower().startswith("0x"):
        try:
            return int(value, 16)
        except ValueError:
            return None
    if len(value) > 1 and value.startswith("0"):
        if any(ch not in "01234567" for ch in value):
            return None
        try:
            return int(value, 8)
        except ValueError:
            return None
    if not value.isdigit():
        return None
    try:
        return int(value, 10)
    except ValueError:
        return None


def _parse_ipv4_legacy_literal(value: str) -> Optional[ipaddress.IPv4Address]:
    parts = value.split(".")
    if not 1 <= len(parts) <= 4:
        return None

    parsed_parts: list[int] = []
    for part in parts:
        parsed = _parse_ipv4_part(part)
        if parsed is None:
            return None
        parsed_parts.append(parsed)

    try:
        if len(parsed_parts) == 1:
            if not 0 <= parsed_parts[0] <= 0xFFFFFFFF:
                return None
            return ipaddress.IPv4Address(parsed_parts[0])
        if len(parsed_parts) == 2:
            first, second = parsed_parts
            if not 0 <= first <= 0xFF or not 0 <= second <= 0xFFFFFF:
                return None
            return ipaddress.IPv4Address((first << 24) | second)
        if len(parsed_parts) == 3:
            first, second, third = parsed_parts
            if not 0 <= first <= 0xFF or not 0 <= second <= 0xFF or not 0 <= third <= 0xFFFF:
                return None
            return ipaddress.IPv4Address((first << 24) | (second << 16) | third)
        if any(not 0 <= part <= 0xFF for part in parsed_parts):
            return None
        first, second, third, fourth = parsed_parts
        return ipaddress.IPv4Address(
            (first << 24) | (second << 16) | (third << 8) | fourth
        )
    except ipaddress.AddressValueError:
        return None


def _target_ip(value: str) -> Optional[ipaddress._BaseAddress]:
    host = _split_host_port(value)
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return _parse_ipv4_legacy_literal(host)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class HTTPRequest:
    """
    Represents a single inbound HTTP request to be evaluated.

    Attributes:
        url:          Full request URL including scheme and host.
        method:       HTTP verb (default ``GET``).
        headers:      Mapping of header name to value.
        query_params: Mapping of parameter name to value or list of values.
        body:         Raw request body string, or ``None``.
        source_ip:    Client source IP address, or ``None``.
    """
    url:          str
    method:       str                     = "GET"
    headers:      Dict[str, Any]          = field(default_factory=dict)
    query_params: Dict[str, Any]          = field(default_factory=dict)
    body:         Optional[str]           = None
    source_ip:    Optional[str]           = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the request to a plain dictionary."""
        return {
            "url":          self.url,
            "method":       self.method,
            "headers":      dict(self.headers),
            "query_params": dict(self.query_params),
            "body":         self.body,
            "source_ip":    self.source_ip,
        }


@dataclass
class SSRFFinding:
    """
    A single SSRF detection finding produced by one rule check.

    Attributes:
        check_id:        Rule identifier (e.g. ``SSRF-001``).
        severity:        Severity string: CRITICAL | HIGH | MEDIUM | LOW | INFO.
        rule_name:       Human-readable rule name.
        matched_value:   First 80 characters of the offending value.
        param_location:  Where the value was found: ``query`` | ``body`` | ``header``.
        recommendation:  Remediation guidance.
    """
    check_id:       str
    severity:       str
    rule_name:      str
    matched_value:  str   # truncated to 80 chars
    param_location: str   # "query" | "body" | "header"
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the finding to a plain dictionary."""
        return {
            "check_id":       self.check_id,
            "severity":       self.severity,
            "rule_name":      self.rule_name,
            "matched_value":  self.matched_value,
            "param_location": self.param_location,
            "recommendation": self.recommendation,
        }


@dataclass
class SSRFEvalResult:
    """
    Aggregated result of evaluating one HTTPRequest against the SSRF rulepack.

    Attributes:
        findings:    List of individual rule findings (may be empty).
        risk_score:  Integer 0–100 computed from unique fired check weights.
        blocked:     ``True`` when any finding meets the pack's block threshold.
    """
    findings:   List[SSRFFinding]
    risk_score: int
    blocked:    bool

    def summary(self) -> str:
        """Return a one-line human-readable summary of the evaluation."""
        action = "BLOCKED" if self.blocked else "ALLOWED"
        count  = len(self.findings)
        return (
            f"[{action}] risk_score={self.risk_score}/100  "
            f"findings={count}  "
            f"severities={list(self.by_severity().keys())}"
        )

    def by_severity(self) -> Dict[str, List[SSRFFinding]]:
        """
        Group findings by severity.

        Returns:
            Dict mapping severity string to list of findings, ordered from
            most severe to least severe.
        """
        groups: Dict[str, List[SSRFFinding]] = {}
        for finding in self.findings:
            groups.setdefault(finding.severity, []).append(finding)
        # Return in severity-descending order
        return dict(
            sorted(
                groups.items(),
                key=lambda kv: _SEVERITY_ORDER.get(kv[0], 0),
                reverse=True,
            )
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the full result to a plain dictionary."""
        return {
            "findings":   [f.to_dict() for f in self.findings],
            "risk_score": self.risk_score,
            "blocked":    self.blocked,
            "summary":    self.summary(),
            "by_severity": {
                sev: [f.to_dict() for f in fs]
                for sev, fs in self.by_severity().items()
            },
        }


# ---------------------------------------------------------------------------
# Helper: extract all candidate string values from a request
# ---------------------------------------------------------------------------

def _extract_values(request: HTTPRequest) -> List[tuple[str, str]]:
    """
    Collect every string value from the request together with its location tag.

    Returns a list of ``(value, location)`` tuples where *location* is one of
    ``"query"``, ``"body"``, or ``"header"``.

    - Query param values are flattened: list values contribute one entry each.
    - The full body string is included as a single entry if not None.
    - Each header value is included individually.
    """
    results: List[tuple[str, str]] = []

    # Query parameters — values may be str or list[str]
    for val in request.query_params.values():
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    results.append((item, "query"))
        elif isinstance(val, str):
            results.append((val, "query"))

    # Request body
    if request.body is not None:
        results.append((request.body, "body"))

    # Header values
    for val in request.headers.values():
        if isinstance(val, str):
            results.append((val, "header"))

    return results


# ---------------------------------------------------------------------------
# SSRFProtectionPack
# ---------------------------------------------------------------------------

class SSRFProtectionPack:
    """
    Evaluates HTTP requests for SSRF attack indicators.

    All checks are performed via regex against extracted string values —
    no live DNS lookups or network connections are made.

    Args:
        block_on_severity: Minimum severity that causes ``blocked=True``.
                           Accepted values (case-insensitive):
                           ``CRITICAL``, ``HIGH``, ``MEDIUM``, ``LOW``, ``INFO``.
                           Default: ``"HIGH"``.

    Example::

        pack = SSRFProtectionPack(block_on_severity="CRITICAL")
        result = pack.evaluate(request)
        if result.blocked:
            return http_403()
    """

    def __init__(self, block_on_severity: str = "HIGH") -> None:
        sev = block_on_severity.upper()
        if sev not in _SEVERITY_ORDER:
            raise ValueError(
                f"Unknown severity '{block_on_severity}'. "
                f"Choose from: {sorted(_SEVERITY_ORDER, key=_SEVERITY_ORDER.get, reverse=True)}"
            )
        self._block_threshold: int = _SEVERITY_ORDER[sev]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, request: HTTPRequest) -> SSRFEvalResult:
        """
        Evaluate a single request against all SSRF rules.

        Args:
            request: The HTTP request to analyse.

        Returns:
            An :class:`SSRFEvalResult` with all findings, risk score,
            and blocked flag.
        """
        value_locs = _extract_values(request)
        findings: List[SSRFFinding] = []

        # Run each check; de-duplicate by check_id so each fires at most once
        fired_ids: set[str] = set()

        for check_fn in (
            self._check_ssrf001_private_ip,
            self._check_ssrf002_loopback,
            self._check_ssrf003_metadata,
            self._check_ssrf004_dns_rebind,
            self._check_ssrf005_scheme,
            self._check_ssrf006_shortener,
            self._check_ssrf007_internal_host,
        ):
            for value, location in value_locs:
                finding = check_fn(value, location)
                if finding is not None and finding.check_id not in fired_ids:
                    findings.append(finding)
                    fired_ids.add(finding.check_id)
                    break  # move to next check once one value triggers it

        # Compute risk score from unique fired check weights
        risk_score = min(100, sum(_CHECK_WEIGHTS.get(cid, 0) for cid in fired_ids))

        # Determine blocked flag
        blocked = any(
            _SEVERITY_ORDER.get(f.severity, 0) >= self._block_threshold
            for f in findings
        )

        return SSRFEvalResult(
            findings=findings,
            risk_score=risk_score,
            blocked=blocked,
        )

    def evaluate_many(self, requests: List[HTTPRequest]) -> List[SSRFEvalResult]:
        """
        Evaluate multiple requests and return one result per request.

        Args:
            requests: List of :class:`HTTPRequest` objects.

        Returns:
            List of :class:`SSRFEvalResult` in the same order as *requests*.
        """
        return [self.evaluate(req) for req in requests]

    # ------------------------------------------------------------------
    # Individual check methods
    # ------------------------------------------------------------------

    def _check_ssrf001_private_ip(
        self, value: str, location: str
    ) -> Optional[SSRFFinding]:
        """SSRF-001: RFC 1918 private IP address in request values."""
        for pattern in _PRIVATE_IP_PATTERNS:
            m = pattern.search(value)
            if m:
                return SSRFFinding(
                    check_id="SSRF-001",
                    severity="CRITICAL",
                    rule_name="RFC1918 Private IP Address",
                    matched_value=value[:80],
                    param_location=location,
                    recommendation=(
                        "Reject or sanitise request values that resolve to RFC 1918 "
                        "private address space (10.x, 172.16-31.x, 192.168.x). "
                        "Implement an allowlist of permitted destination hosts and "
                        "validate resolved IPs before making outbound connections."
                    ),
                )
        ip = _target_ip(value)
        if isinstance(ip, ipaddress.IPv4Address) and any(ip in network for network in _PRIVATE_IP_NETWORKS):
            return SSRFFinding(
                check_id="SSRF-001",
                severity="CRITICAL",
                rule_name="RFC1918 Private IP Address",
                matched_value=value[:80],
                param_location=location,
                recommendation=(
                    "Reject or sanitise request values that resolve to RFC 1918 "
                    "private address space (10.x, 172.16-31.x, 192.168.x). "
                    "Implement an allowlist of permitted destination hosts and "
                    "validate resolved IPs before making outbound connections."
                ),
            )
        return None

    def _check_ssrf002_loopback(
        self, value: str, location: str
    ) -> Optional[SSRFFinding]:
        """SSRF-002: Localhost / loopback reference."""
        for pattern in _LOOPBACK_PATTERNS:
            if pattern.search(value):
                return SSRFFinding(
                    check_id="SSRF-002",
                    severity="CRITICAL",
                    rule_name="Localhost / Loopback Reference",
                    matched_value=value[:80],
                    param_location=location,
                    recommendation=(
                        "Block any request value referencing loopback addresses "
                        "(localhost, 127.x.x.x, ::1, 0.0.0.0). Enforce an allowlist "
                        "of resolvable public hostnames and deny connections to the "
                        "server's own loopback interface."
                    ),
                )
        ip = _target_ip(value)
        if ip is not None and (ip.is_loopback or ip.is_unspecified):
            return SSRFFinding(
                check_id="SSRF-002",
                severity="CRITICAL",
                rule_name="Localhost / Loopback Reference",
                matched_value=value[:80],
                param_location=location,
                recommendation=(
                    "Block any request value referencing loopback addresses "
                    "(localhost, 127.x.x.x, ::1, 0.0.0.0). Enforce an allowlist "
                    "of resolvable public hostnames and deny connections to the "
                    "server's own loopback interface."
                ),
            )
        return None

    def _check_ssrf003_metadata(
        self, value: str, location: str
    ) -> Optional[SSRFFinding]:
        """SSRF-003: Cloud metadata endpoint address."""
        for pattern in _METADATA_PATTERNS:
            if pattern.search(value):
                return SSRFFinding(
                    check_id="SSRF-003",
                    severity="CRITICAL",
                    rule_name="Cloud Metadata Endpoint",
                    matched_value=value[:80],
                    param_location=location,
                    recommendation=(
                        "Block requests to cloud instance metadata endpoints "
                        "(169.254.169.254, 169.254.170.2, metadata.google.internal, "
                        "fd00:ec2::254). Use IMDSv2 with PUT-based tokens and restrict "
                        "outbound connectivity from application servers at the network layer."
                    ),
                )
        ip = _target_ip(value)
        if ip in _METADATA_IPS:
            return SSRFFinding(
                check_id="SSRF-003",
                severity="CRITICAL",
                rule_name="Cloud Metadata Endpoint",
                matched_value=value[:80],
                param_location=location,
                recommendation=(
                    "Block requests to cloud instance metadata endpoints "
                    "(169.254.169.254, 169.254.170.2, metadata.google.internal, "
                    "fd00:ec2::254). Use IMDSv2 with PUT-based tokens and restrict "
                    "outbound connectivity from application servers at the network layer."
                ),
            )
        return None

    def _check_ssrf004_dns_rebind(
        self, value: str, location: str
    ) -> Optional[SSRFFinding]:
        """SSRF-004: DNS rebinding indicator."""
        if _DNS_REBIND_BARE_RE.search(value):
            return SSRFFinding(
                check_id="SSRF-004",
                severity="HIGH",
                rule_name="DNS Rebinding Indicator",
                matched_value=value[:80],
                param_location=location,
                recommendation=(
                    "Block hostnames from known DNS rebinding services "
                    "(*.nip.io, *.xip.io, *.sslip.io, *.traefik.me, "
                    "*.localtest.me, *.lvh.me). Validate that resolved IP addresses "
                    "are not within private, loopback, or link-local ranges after DNS "
                    "resolution."
                ),
            )
        return None

    def _check_ssrf005_scheme(
        self, value: str, location: str
    ) -> Optional[SSRFFinding]:
        """SSRF-005: Non-HTTP/HTTPS URL scheme."""
        if "://" not in value:
            return None
        m = _SCHEME_RE.search(value)
        if not m:
            return None
        scheme = m.group(1).lower()
        if scheme in _DANGEROUS_SCHEMES:
            return SSRFFinding(
                check_id="SSRF-005",
                severity="HIGH",
                rule_name="Dangerous URL Scheme",
                matched_value=value[:80],
                param_location=location,
                recommendation=(
                    f"The scheme '{scheme}://' is not permitted. "
                    "Only allow 'http' and 'https' schemes for outbound "
                    "request targets. Reject or URL-encode any other scheme "
                    "before passing the value to HTTP client libraries."
                ),
            )
        return None

    def _check_ssrf006_shortener(
        self, value: str, location: str
    ) -> Optional[SSRFFinding]:
        """SSRF-006: URL shortener / redirect service abuse."""
        # Check against known shortener domain list
        value_lower = value.lower()
        for domain in _SHORTENER_DOMAINS:
            if domain in value_lower:
                return SSRFFinding(
                    check_id="SSRF-006",
                    severity="MEDIUM",
                    rule_name="URL Shortener / Redirect Abuse",
                    matched_value=value[:80],
                    param_location=location,
                    recommendation=(
                        f"URL shortener '{domain}' detected. Short URLs obscure the "
                        "final destination and can redirect to internal resources. "
                        "Expand and validate all redirect chains before making "
                        "outbound requests, or maintain an allowlist of approved domains."
                    ),
                )
        return None

    def _check_ssrf007_internal_host(
        self, value: str, location: str
    ) -> Optional[SSRFFinding]:
        """SSRF-007: Internal service hostname pattern."""
        # Check internal TLD suffixes
        if _INTERNAL_TLD_RE.search(value):
            return SSRFFinding(
                check_id="SSRF-007",
                severity="HIGH",
                rule_name="Internal Service Hostname",
                matched_value=value[:80],
                param_location=location,
                recommendation=(
                    "Hostname resolves to an internal TLD "
                    "(.internal, .local, .corp, .intranet, .lan, .home, .localdomain). "
                    "Enforce a strict allowlist of approved external hostnames. "
                    "Deny all requests to internal service discovery domains."
                ),
            )
        # Check internal service names (redis, elasticsearch, etc.)
        if _INTERNAL_SERVICE_RE.search(value):
            return SSRFFinding(
                check_id="SSRF-007",
                severity="HIGH",
                rule_name="Internal Service Hostname",
                matched_value=value[:80],
                param_location=location,
                recommendation=(
                    "A well-known internal service name (redis, elasticsearch, kafka, "
                    "etc.) was detected in the request value. These hostnames typically "
                    "resolve only within the internal network. Validate and restrict "
                    "outbound request targets to an approved allowlist."
                ),
            )
        return None
