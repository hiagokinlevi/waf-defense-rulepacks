# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) 2026 Hiago Kin Levi
# Licensed under the Creative Commons Attribution 4.0 International License.
# https://creativecommons.org/licenses/by/4.0/
"""
LFI / RFI Protection Rulepack
==============================
WAF rulepack that detects Local File Inclusion (LFI) and Remote File Inclusion
(RFI) attack patterns in HTTP request parameters, body, and headers.  All
analysis is performed locally with compiled regular expressions and stdlib
``urllib.parse`` — no external dependencies are required.

Rule Catalogue
--------------
LFI-001  Path traversal sequences  (``../`` or ``..\\``)            (CRITICAL)
LFI-002  Null-byte injection  (``%00`` / ``\\x00``)                  (HIGH)
LFI-003  PHP / data stream wrapper schemes                           (HIGH)
LFI-004  Remote file inclusion URL in file-context parameter         (CRITICAL)
LFI-005  URL-encoded path traversal  (``%2e%2e%2f`` etc.)           (CRITICAL)
LFI-006  Double-encoded path traversal  (``%252e%252e%252f`` etc.)  (HIGH)
LFI-007  Sensitive OS file target patterns                           (HIGH)

Usage::

    from shared.rulepacks.lfi_rfi_pack import HTTPRequest, LFIRFIPack

    pack = LFIRFIPack(block_on_severity="HIGH")
    result = pack.evaluate(
        HTTPRequest(
            url="https://example.com/page",
            query_params={"file": "../../../etc/passwd"},
        )
    )
    print(result.summary())   # [BLOCKED] risk_score=45/100 ...
    print(result.blocked)     # True
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Severity ordering (used for block-threshold comparison)
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
    "INFO":     0,
}


# ---------------------------------------------------------------------------
# Check weights — risk_score = min(100, sum of weights for unique fired IDs)
# ---------------------------------------------------------------------------

_CHECK_WEIGHTS: Dict[str, int] = {
    "LFI-001": 45,  # Path traversal sequences
    "LFI-002": 30,  # Null-byte injection
    "LFI-003": 30,  # PHP wrapper schemes
    "LFI-004": 45,  # Remote file inclusion URL
    "LFI-005": 45,  # URL-encoded path traversal
    "LFI-006": 30,  # Double-encoded path traversal
    "LFI-007": 25,  # Sensitive OS file target patterns
}


# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# LFI-001 — Raw path traversal (forward slash or backslash)
_TRAVERSAL_RAW_RE = re.compile(r'\.\.[/\\]')

# LFI-002 — Null-byte injection (%00 encoding or literal \x00)
_NULL_BYTE_RE = re.compile(r'%00|\x00')

# LFI-003 — PHP / data stream wrapper schemes (case-insensitive)
_PHP_WRAPPER_RE = re.compile(
    r'(php|data|expect|zip|phar|glob|compress\.zlib|compress\.bzip2)://',
    re.IGNORECASE,
)

# LFI-004 — Remote file inclusion: URL-like value in a file-context param name
_RFI_URL_RE = re.compile(r'(https?|ftp)://', re.IGNORECASE)
# Param name keywords that indicate a file-loading context
_FILE_CONTEXT_KEYWORDS: frozenset = frozenset([
    "file", "path", "include", "require", "page", "template",
    "load", "read", "fetch", "url", "src", "source",
    "doc", "document",
])

# LFI-005 — Single URL-encoded path traversal (%2e%2e%2f / %2e%2e/ etc.)
# Detected after a single urllib.parse.unquote() pass; pattern reuses LFI-001.

# LFI-006 — Double URL-encoded path traversal (%252e%252e%252f etc.)
# Detected after two urllib.parse.unquote() passes; reuses LFI-001 pattern.

# LFI-007 — Sensitive OS file target patterns (case-insensitive)
_SENSITIVE_FILE_PATTERNS: List[re.Pattern] = [
    re.compile(r'/etc/passwd',         re.IGNORECASE),
    re.compile(r'/etc/shadow',         re.IGNORECASE),
    re.compile(r'/etc/hosts',          re.IGNORECASE),
    re.compile(r'/proc/self',          re.IGNORECASE),
    re.compile(r'/proc/version',       re.IGNORECASE),
    re.compile(r'windows[/\\]system32',re.IGNORECASE),
    re.compile(r'win\.ini',            re.IGNORECASE),
    re.compile(r'boot\.ini',           re.IGNORECASE),
    re.compile(r'autoexec\.bat',       re.IGNORECASE),
    re.compile(r'/\.ssh/',             re.IGNORECASE),
    re.compile(r'/\.env',              re.IGNORECASE),
    re.compile(r'/wp-config\.php',     re.IGNORECASE),
    re.compile(r'/config\.php',        re.IGNORECASE),
]


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
        query_params: Mapping of parameter name to value or list of values.
        body:         Raw request body string, or ``None``.
        headers:      Mapping of header name to value.
    """
    url:          str
    method:       str            = "GET"
    query_params: Dict[str, Any] = field(default_factory=dict)
    body:         Optional[str]  = None
    headers:      Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the request to a plain dictionary."""
        return {
            "url":          self.url,
            "method":       self.method,
            "query_params": dict(self.query_params),
            "body":         self.body,
            "headers":      dict(self.headers),
        }


@dataclass
class LFIFinding:
    """
    A single LFI/RFI detection finding produced by one rule check.

    Attributes:
        check_id:        Rule identifier (e.g. ``LFI-001``).
        severity:        Severity string: CRITICAL | HIGH | MEDIUM | LOW | INFO.
        rule_name:       Human-readable rule name.
        matched_value:   First 100 characters of the offending value.
        param_location:  Where the value was found: ``query`` | ``body`` |
                         ``header`` | ``url``.
        recommendation:  Remediation guidance.
    """
    check_id:       str
    severity:       str
    rule_name:      str
    matched_value:  str   # truncated to 100 chars
    param_location: str   # "query" | "body" | "header" | "url"
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
class LFIEvalResult:
    """
    Aggregated result of evaluating one HTTPRequest against the LFI/RFI pack.

    Attributes:
        findings:    List of individual rule findings (may be empty).
        risk_score:  Integer 0–100 computed from unique fired check weights.
        blocked:     ``True`` when any finding meets the pack's block threshold.
    """
    findings:   List[LFIFinding]
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

    def by_severity(self) -> Dict[str, List[LFIFinding]]:
        """
        Group findings by severity.

        Returns:
            Dict mapping severity string to list of findings, ordered from
            most severe to least severe.
        """
        groups: Dict[str, List[LFIFinding]] = {}
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
            "findings":    [f.to_dict() for f in self.findings],
            "risk_score":  self.risk_score,
            "blocked":     self.blocked,
            "summary":     self.summary(),
            "by_severity": {
                sev: [f.to_dict() for f in fs]
                for sev, fs in self.by_severity().items()
            },
        }


# ---------------------------------------------------------------------------
# Helper: extract all candidate string values from a request
# ---------------------------------------------------------------------------

def _extract_values(request: HTTPRequest) -> List[tuple]:
    """
    Collect every string value from the request together with its location tag.

    Returns a list of ``(value, location)`` tuples where *location* is one of
    ``"query"``, ``"body"``, or ``"header"``.

    - Query param values are flattened: list values contribute one entry each.
    - The full body string is included as a single entry when not ``None``.
    - Each header value is included individually.
    """
    results: List[tuple] = []

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
# LFIRFIPack
# ---------------------------------------------------------------------------

class LFIRFIPack:
    """
    Evaluates HTTP requests for LFI and RFI attack indicators.

    All checks are performed locally via regex and stdlib URL decoding —
    no external libraries or network calls are made.

    Args:
        block_on_severity: Minimum severity that causes ``blocked=True``.
                           Accepted values (case-insensitive):
                           ``CRITICAL``, ``HIGH``, ``MEDIUM``, ``LOW``, ``INFO``.
                           Default: ``"HIGH"``.

    Example::

        pack = LFIRFIPack(block_on_severity="CRITICAL")
        result = pack.evaluate(request)
        if result.blocked:
            return http_403()
    """

    def __init__(self, block_on_severity: str = "HIGH") -> None:
        sev = block_on_severity.upper()
        if sev not in _SEVERITY_ORDER:
            raise ValueError(
                f"Unknown severity '{block_on_severity}'. "
                f"Choose from: {sorted(_SEVERITY_ORDER, key=_SEVERITY_ORDER.get, reverse=True)}"  # type: ignore[arg-type]
            )
        self._block_threshold: int = _SEVERITY_ORDER[sev]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, request: HTTPRequest) -> LFIEvalResult:
        """
        Evaluate a single request against all LFI/RFI rules.

        Args:
            request: The HTTP request to analyse.

        Returns:
            An :class:`LFIEvalResult` with all findings, risk score,
            and blocked flag.
        """
        value_locs = _extract_values(request)
        findings: List[LFIFinding] = []
        fired_ids: set = set()

        for check_fn in (
            self._check_lfi001_path_traversal,
            self._check_lfi002_null_byte,
            self._check_lfi003_php_wrapper,
            self._check_lfi004_rfi_url,
            self._check_lfi005_encoded_traversal,
            self._check_lfi006_double_encoded_traversal,
            self._check_lfi007_sensitive_file,
        ):
            # Each check also receives the full request for URL-level inspection
            for value, location in value_locs:
                finding = check_fn(value, location, request)  # type: ignore[call-arg]
                if finding is not None and finding.check_id not in fired_ids:
                    findings.append(finding)
                    fired_ids.add(finding.check_id)
                    break  # move to next check once one value triggers it

            # If not yet fired, run URL-level check for this rule
            if check_fn.__name__.endswith(('001_path_traversal', '005_encoded_traversal')):
                check_id = "LFI-001" if "001" in check_fn.__name__ else "LFI-005"
                if check_id not in fired_ids:
                    url_finding = check_fn(request.url, "url", request)  # type: ignore[call-arg]
                    if url_finding is not None:
                        findings.append(url_finding)
                        fired_ids.add(url_finding.check_id)

        # Compute risk score from unique fired check weights
        risk_score = min(100, sum(_CHECK_WEIGHTS.get(cid, 0) for cid in fired_ids))

        # Determine blocked flag
        blocked = any(
            _SEVERITY_ORDER.get(f.severity, 0) >= self._block_threshold
            for f in findings
        )

        return LFIEvalResult(
            findings=findings,
            risk_score=risk_score,
            blocked=blocked,
        )

    def evaluate_many(self, requests: List[HTTPRequest]) -> List[LFIEvalResult]:
        """
        Evaluate multiple requests and return one result per request.

        Args:
            requests: List of :class:`HTTPRequest` objects.

        Returns:
            List of :class:`LFIEvalResult` in the same order as *requests*.
        """
        return [self.evaluate(req) for req in requests]

    # ------------------------------------------------------------------
    # Individual check methods
    # Each accepts (value, location, request) so URL-level checks can
    # re-use the same method with location="url".
    # ------------------------------------------------------------------

    def _check_lfi001_path_traversal(
        self, value: str, location: str, request: HTTPRequest
    ) -> Optional[LFIFinding]:
        r"""LFI-001: Raw path traversal sequences (``../`` or ``..\``)."""
        if _TRAVERSAL_RAW_RE.search(value):
            return LFIFinding(
                check_id="LFI-001",
                severity="CRITICAL",
                rule_name="Path Traversal Sequence",
                matched_value=value[:100],
                param_location=location,
                recommendation=(
                    "Reject request values that contain ``../`` or ``..\\\\ `` "
                    "sequences. Canonicalise file paths using os.path.realpath() "
                    "and enforce that the resolved path starts with the expected "
                    "base directory. Never pass raw user input to file-open calls."
                ),
            )
        return None

    def _check_lfi002_null_byte(
        self, value: str, location: str, request: HTTPRequest
    ) -> Optional[LFIFinding]:
        """LFI-002: Null-byte injection (``%00`` or literal ``\\x00``)."""
        if _NULL_BYTE_RE.search(value):
            return LFIFinding(
                check_id="LFI-002",
                severity="HIGH",
                rule_name="Null Byte Injection",
                matched_value=value[:100],
                param_location=location,
                recommendation=(
                    "Strip or reject null bytes (``%00`` / ``\\x00``) from all "
                    "request values before use. C-based runtimes (PHP, C extensions) "
                    "truncate strings at null bytes, allowing attackers to bypass "
                    "extension checks (e.g. ``file.php%00.txt`` → opens ``file.php``)."
                ),
            )
        return None

    def _check_lfi003_php_wrapper(
        self, value: str, location: str, request: HTTPRequest
    ) -> Optional[LFIFinding]:
        """LFI-003: PHP / data stream wrapper schemes."""
        if _PHP_WRAPPER_RE.search(value):
            return LFIFinding(
                check_id="LFI-003",
                severity="HIGH",
                rule_name="PHP / Data Stream Wrapper",
                matched_value=value[:100],
                param_location=location,
                recommendation=(
                    "Disallow PHP stream wrapper schemes (php://, phar://, data://, "
                    "expect://, zip://, glob://, compress.zlib://, compress.bzip2://) "
                    "in file-path parameters. Use a strict allowlist of permitted "
                    "file extensions and validate inputs against it before inclusion."
                ),
            )
        return None

    def _check_lfi004_rfi_url(
        self, value: str, location: str, request: HTTPRequest
    ) -> Optional[LFIFinding]:
        """LFI-004: Remote file inclusion URL in a file-context parameter name."""
        if not _RFI_URL_RE.search(value):
            return None

        # Check param names from query_params for file-context keywords
        for param_name, param_val in request.query_params.items():
            param_lower = param_name.lower()
            # Does the param name contain a file-context keyword?
            if any(kw in param_lower for kw in _FILE_CONTEXT_KEYWORDS):
                # Does its value (or one of its values if a list) contain a URL?
                vals = param_val if isinstance(param_val, list) else [param_val]
                for v in vals:
                    if isinstance(v, str) and _RFI_URL_RE.search(v):
                        return LFIFinding(
                            check_id="LFI-004",
                            severity="CRITICAL",
                            rule_name="Remote File Inclusion URL",
                            matched_value=v[:100],
                            param_location="query",
                            recommendation=(
                                "Reject external URLs in file-loading parameters "
                                "(file, path, include, page, template, etc.). "
                                "Use a server-side allowlist of permitted file names or "
                                "identifiers and never pass remote URLs to include/require "
                                "or equivalent calls."
                            ),
                        )

        # If the current value matched a URL pattern but no file-context param
        # was found, check whether it was passed in body or header with the value
        # itself matching; only fire if the *calling location* is body/header and
        # the value is a URL (conservative — avoids false positives on plain links).
        # For body/header we require explicit URL match (already confirmed above).
        if location in ("body", "header") and _RFI_URL_RE.search(value):
            # For body/header, fire only when the surrounding context provides no
            # param name — apply a conservative pass-through so we don't over-block.
            # (Implementors may relax this by inspecting structured body content.)
            pass

        return None

    def _check_lfi005_encoded_traversal(
        self, value: str, location: str, request: HTTPRequest
    ) -> Optional[LFIFinding]:
        """LFI-005: Single URL-encoded path traversal (``%2e%2e%2f`` etc.)."""
        decoded = urllib.parse.unquote(value)
        # Fire only when the decoded form contains traversal but the raw form
        # does NOT (raw traversal is already covered by LFI-001).
        if _TRAVERSAL_RAW_RE.search(decoded) and not _TRAVERSAL_RAW_RE.search(value):
            return LFIFinding(
                check_id="LFI-005",
                severity="CRITICAL",
                rule_name="URL-Encoded Path Traversal",
                matched_value=value[:100],
                param_location=location,
                recommendation=(
                    "Decode all URL percent-encoding (single pass) before validating "
                    "path values. Reject decoded values that contain ``../`` or ``..\\\\``. "
                    "Canonicalise the resolved path and verify it is within the "
                    "permitted base directory."
                ),
            )
        return None

    def _check_lfi006_double_encoded_traversal(
        self, value: str, location: str, request: HTTPRequest
    ) -> Optional[LFIFinding]:
        """LFI-006: Double URL-encoded path traversal (``%252e%252e%252f`` etc.)."""
        once   = urllib.parse.unquote(value)
        twice  = urllib.parse.unquote(once)
        # Fire only when double-decoding reveals traversal but single-decoding does not
        if _TRAVERSAL_RAW_RE.search(twice) and not _TRAVERSAL_RAW_RE.search(once):
            return LFIFinding(
                check_id="LFI-006",
                severity="HIGH",
                rule_name="Double-Encoded Path Traversal",
                matched_value=value[:100],
                param_location=location,
                recommendation=(
                    "Apply recursive URL decoding until the value stabilises, then "
                    "validate for path traversal sequences. Reject values that require "
                    "more than one decoding pass to normalise, as this indicates "
                    "deliberate evasion of single-pass filters."
                ),
            )
        return None

    def _check_lfi007_sensitive_file(
        self, value: str, location: str, request: HTTPRequest
    ) -> Optional[LFIFinding]:
        """LFI-007: Sensitive OS file target patterns."""
        for pattern in _SENSITIVE_FILE_PATTERNS:
            if pattern.search(value):
                return LFIFinding(
                    check_id="LFI-007",
                    severity="HIGH",
                    rule_name="Sensitive OS File Target",
                    matched_value=value[:100],
                    param_location=location,
                    recommendation=(
                        "Reject request values that reference well-known sensitive "
                        "system files (/etc/passwd, /etc/shadow, win.ini, etc.). "
                        "Maintain a server-side mapping from logical names to absolute "
                        "paths and never expose OS file paths directly to user input."
                    ),
                )
        return None
