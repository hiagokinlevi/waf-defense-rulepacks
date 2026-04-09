# xss_detection_pack.py — Cyber Port WAF Rulepack
#
# Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# Part of the Cyber Port portfolio: github.com/hiagokinlevi
# Detects Cross-Site Scripting (XSS) attempts in HTTP request parameters,
# headers, and body — covering reflected, DOM-based, CSS-based, event handler,
# HTML5/SVG vectors, and obfuscated/encoded variants.

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Severity ordering for comparison
# ---------------------------------------------------------------------------
_SEVERITY_ORDER: Dict[str, int] = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# ---------------------------------------------------------------------------
# Check weights dictionary
# ---------------------------------------------------------------------------
_CHECK_WEIGHTS: Dict[str, int] = {
    "XSS-001": 45,  # Reflected XSS — script/javascript/vbscript/data URI
    "XSS-002": 30,  # DOM-based XSS sinks
    "XSS-003": 25,  # CSS-based XSS (expression/url(javascript:)/behavior)
    "XSS-004": 30,  # Event handler injection (on[a-z]+=)
    "XSS-005": 45,  # SVG/HTML5 XSS vectors
    "XSS-006": 25,  # URL/percent-encoded XSS bypass
    "XSS-007": 25,  # HTML entity or double-encoded XSS
}

# ---------------------------------------------------------------------------
# Compiled patterns for each check
# ---------------------------------------------------------------------------

# XSS-001: Reflected XSS
_PATTERNS_001: List[re.Pattern] = [
    re.compile(r"<script", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"vbscript\s*:", re.IGNORECASE),
    re.compile(r"data\s*:\s*text/html", re.IGNORECASE),
    re.compile(r"data\s*:\s*application/javascript", re.IGNORECASE),
]

# XSS-002: DOM-based XSS sinks
_PATTERNS_002: List[re.Pattern] = [
    re.compile(r"document\.write\s*\(", re.IGNORECASE),
    re.compile(r"\.innerHTML\s*=", re.IGNORECASE),
    re.compile(r"\.outerHTML\s*=", re.IGNORECASE),
    re.compile(r"\beval\s*\(", re.IGNORECASE),
    re.compile(r"setTimeout\s*\(", re.IGNORECASE),
    re.compile(r"setInterval\s*\(", re.IGNORECASE),
    re.compile(r"\bFunction\s*\(", re.IGNORECASE),
]

# XSS-003: CSS-based XSS
_PATTERNS_003: List[re.Pattern] = [
    re.compile(r"expression\s*\(", re.IGNORECASE),
    re.compile(r"url\s*\(\s*javascript\s*:", re.IGNORECASE),
    re.compile(r"behavior\s*:\s*url", re.IGNORECASE),
    re.compile(r"@import", re.IGNORECASE),
    re.compile(r"-moz-binding\s*:\s*url", re.IGNORECASE),
]

# XSS-004: Event handler injection
_PATTERNS_004: List[re.Pattern] = [
    re.compile(r"on[a-z]{2,20}\s*=\s*[^>]{1,200}", re.IGNORECASE),
]

# XSS-005: SVG/HTML5 XSS vectors
_PATTERNS_005: List[re.Pattern] = [
    re.compile(r"<svg[\s>]", re.IGNORECASE),
    re.compile(r"<iframe[\s>]", re.IGNORECASE),
    re.compile(r"<object[\s>]", re.IGNORECASE),
    re.compile(r"<embed[\s>]", re.IGNORECASE),
    re.compile(r"<img\s[^>]*onerror", re.IGNORECASE),
    re.compile(r"<details[\s>]", re.IGNORECASE),
    re.compile(r"<body\s[^>]*onload", re.IGNORECASE),
    re.compile(r"<marquee[\s>]", re.IGNORECASE),
]

# XSS-007: HTML entity / double-encoded / unicode escape patterns
_PATTERNS_007: List[re.Pattern] = [
    # Hex HTML entities for <, >, ", ', /
    re.compile(r"&#x[0-9a-fA-F]+;", re.IGNORECASE),
    # Decimal HTML entities for <, >, ", ', /
    re.compile(r"&#\d+;", re.IGNORECASE),
    # Double percent-encoded (e.g., %253C = double-encoded <)
    re.compile(r"%25[0-9a-fA-F]{2}", re.IGNORECASE),
    # Unicode escape sequences (e.g., \u003C)
    re.compile(r"\\u00[0-9a-fA-F]{2}", re.IGNORECASE),
]

# Specific dangerous entity targets for XSS-007
_ENTITY_TARGETS: List[re.Pattern] = [
    re.compile(r"&#x3[cC];?", re.IGNORECASE),   # &#x3c; = <
    re.compile(r"&#60;?", re.IGNORECASE),         # &#60; = <
    re.compile(r"%253[cC]", re.IGNORECASE),       # %253C = double-encoded <
    re.compile(r"\\u003[cC]", re.IGNORECASE),     # \u003C = unicode <
]

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class XSSFinding:
    """Represents a single XSS detection finding."""

    check_id: str         # e.g. "XSS-001"
    severity: str         # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str            # Human-readable check title
    detail: str           # Explanation of what was detected
    weight: int           # Numeric weight for risk scoring
    parameter: str        # Which param / header / body triggered the finding
    evidence: str         # Matching portion truncated to 100 characters


@dataclass
class XSSResult:
    """Aggregated result of running the XSS rulepack against one HTTP request."""

    findings: List[XSSFinding] = field(default_factory=list)
    risk_score: int = 0   # min(100, sum of weights for fired unique checks)
    blocked: bool = False  # True if any CRITICAL finding (or per block_on_severity)

    def to_dict(self) -> dict:
        """Serialize the result to a plain dictionary."""
        return {
            "findings": [
                {
                    "check_id": f.check_id,
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "weight": f.weight,
                    "parameter": f.parameter,
                    "evidence": f.evidence,
                }
                for f in self.findings
            ],
            "risk_score": self.risk_score,
            "blocked": self.blocked,
        }

    def summary(self) -> str:
        """Return a one-line summary of the result."""
        if not self.findings:
            return "XSS: CLEAN — no findings (risk_score=0)"
        ids = ", ".join(sorted({f.check_id for f in self.findings}))
        status = "BLOCKED" if self.blocked else "FLAGGED"
        return (
            f"XSS: {status} — checks fired: {ids} "
            f"(risk_score={self.risk_score})"
        )

    def by_severity(self) -> Dict[str, List[XSSFinding]]:
        """Group findings by severity level."""
        groups: Dict[str, List[XSSFinding]] = {}
        for finding in self.findings:
            groups.setdefault(finding.severity, []).append(finding)
        return groups


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _truncate(text: str, max_len: int = 100) -> str:
    """Truncate evidence string to max_len characters."""
    if len(text) <= max_len:
        return text
    return text[:max_len]


def _first_match(patterns: List[re.Pattern], value: str) -> Optional[str]:
    """Return the first matching portion found by any pattern, or None."""
    for pattern in patterns:
        match = pattern.search(value)
        if match:
            return match.group(0)
    return None


def _any_match(patterns: List[re.Pattern], value: str) -> bool:
    """Return True if any pattern matches the value."""
    return _first_match(patterns, value) is not None


def _collect_pairs(
    params: Optional[Dict[str, str]],
    headers: Optional[Dict[str, str]],
    body: Optional[str],
) -> List[Tuple[str, str]]:
    """Collect all (parameter_name, value) pairs from params, headers, body."""
    pairs: List[Tuple[str, str]] = []
    if params:
        for k, v in params.items():
            pairs.append((str(k), str(v)))
    if headers:
        for k, v in headers.items():
            pairs.append((str(k), str(v)))
    if body is not None:
        pairs.append(("body", str(body)))
    return pairs


def _severity_gte(severity: str, threshold: str) -> bool:
    """Return True if severity is greater than or equal to threshold."""
    return _SEVERITY_ORDER.get(severity, 0) >= _SEVERITY_ORDER.get(threshold, 0)


# ---------------------------------------------------------------------------
# Individual check functions — each returns an XSSFinding or None
# ---------------------------------------------------------------------------

def _check_001(param: str, value: str) -> Optional[XSSFinding]:
    """XSS-001: Reflected XSS detection."""
    evidence_raw = _first_match(_PATTERNS_001, value)
    if evidence_raw is None:
        return None
    return XSSFinding(
        check_id="XSS-001",
        severity="CRITICAL",
        title="Reflected XSS Detected",
        detail=(
            "Value contains a reflected XSS vector: script tag, javascript: scheme, "
            "vbscript: scheme, or dangerous data: URI."
        ),
        weight=_CHECK_WEIGHTS["XSS-001"],
        parameter=param,
        evidence=_truncate(evidence_raw),
    )


def _check_002(param: str, value: str) -> Optional[XSSFinding]:
    """XSS-002: DOM-based XSS sink detection."""
    evidence_raw = _first_match(_PATTERNS_002, value)
    if evidence_raw is None:
        return None
    return XSSFinding(
        check_id="XSS-002",
        severity="HIGH",
        title="DOM-based XSS Sink Detected",
        detail=(
            "Value contains a DOM-based XSS sink: document.write, innerHTML, "
            "outerHTML, eval, setTimeout, setInterval, or Function constructor."
        ),
        weight=_CHECK_WEIGHTS["XSS-002"],
        parameter=param,
        evidence=_truncate(evidence_raw),
    )


def _check_003(param: str, value: str) -> Optional[XSSFinding]:
    """XSS-003: CSS-based XSS detection."""
    evidence_raw = _first_match(_PATTERNS_003, value)
    if evidence_raw is None:
        return None
    return XSSFinding(
        check_id="XSS-003",
        severity="HIGH",
        title="CSS-based XSS Detected",
        detail=(
            "Value contains a CSS-based XSS vector: expression(), url(javascript:), "
            "behavior:url, @import, or -moz-binding:url."
        ),
        weight=_CHECK_WEIGHTS["XSS-003"],
        parameter=param,
        evidence=_truncate(evidence_raw),
    )


def _check_004(param: str, value: str) -> Optional[XSSFinding]:
    """XSS-004: Event handler injection detection."""
    evidence_raw = _first_match(_PATTERNS_004, value)
    if evidence_raw is None:
        return None
    return XSSFinding(
        check_id="XSS-004",
        severity="HIGH",
        title="Event Handler Injection Detected",
        detail=(
            "Value contains an inline event handler attribute (e.g., onerror=, "
            "onload=, onclick=, onmouseover=) with a non-empty handler body."
        ),
        weight=_CHECK_WEIGHTS["XSS-004"],
        parameter=param,
        evidence=_truncate(evidence_raw),
    )


def _check_005(param: str, value: str) -> Optional[XSSFinding]:
    """XSS-005: SVG/HTML5 XSS vector detection."""
    evidence_raw = _first_match(_PATTERNS_005, value)
    if evidence_raw is None:
        return None
    return XSSFinding(
        check_id="XSS-005",
        severity="CRITICAL",
        title="SVG/HTML5 XSS Vector Detected",
        detail=(
            "Value contains an HTML5 or SVG XSS vector: <svg>, <iframe>, <object>, "
            "<embed>, <img onerror>, <details>, <body onload>, or <marquee>."
        ),
        weight=_CHECK_WEIGHTS["XSS-005"],
        parameter=param,
        evidence=_truncate(evidence_raw),
    )


def _check_006(
    param: str,
    value: str,
    raw_fired_001: bool,
    raw_fired_004: bool,
    raw_fired_005: bool,
) -> Optional[XSSFinding]:
    """XSS-006: URL/percent-encoded XSS bypass detection.

    URL-decode the value; if decoded != raw AND decoded triggers XSS-001/004/005
    and the raw form did NOT already trigger those checks, fire XSS-006.
    """
    decoded = urllib.parse.unquote(value)
    if decoded == value:
        # No URL encoding present — skip
        return None

    # Check whether decoded triggers XSS-001, XSS-004, or XSS-005
    decoded_001 = _any_match(_PATTERNS_001, decoded)
    decoded_004 = _any_match(_PATTERNS_004, decoded)
    decoded_005 = _any_match(_PATTERNS_005, decoded)

    fires = (
        (decoded_001 and not raw_fired_001)
        or (decoded_004 and not raw_fired_004)
        or (decoded_005 and not raw_fired_005)
    )
    if not fires:
        return None

    # Collect evidence from whichever decoded check fired
    evidence_raw = (
        _first_match(_PATTERNS_001, decoded)
        or _first_match(_PATTERNS_004, decoded)
        or _first_match(_PATTERNS_005, decoded)
        or decoded[:100]
    )
    return XSSFinding(
        check_id="XSS-006",
        severity="HIGH",
        title="URL-encoded XSS Bypass Detected",
        detail=(
            "Value is URL-encoded; when decoded it reveals an XSS vector that was "
            "not detected in the raw form (reflected, event handler, or HTML5/SVG)."
        ),
        weight=_CHECK_WEIGHTS["XSS-006"],
        parameter=param,
        evidence=_truncate(str(evidence_raw)),
    )


def _check_007(param: str, value: str) -> Optional[XSSFinding]:
    """XSS-007: HTML entity or double-encoded XSS detection."""
    # First check for specific dangerous entity targets
    for pattern in _ENTITY_TARGETS:
        match = pattern.search(value)
        if match:
            return XSSFinding(
                check_id="XSS-007",
                severity="HIGH",
                title="HTML Entity / Double-encoded XSS Detected",
                detail=(
                    "Value contains HTML entity encoding, double percent-encoding, "
                    "or unicode escape sequences targeting dangerous characters "
                    "(&#x3C;, &#60;, %253C, \\u003C)."
                ),
                weight=_CHECK_WEIGHTS["XSS-007"],
                parameter=param,
                evidence=_truncate(match.group(0)),
            )

    # Fallback: generic entity/escape patterns — only flag if they encode
    # characters that are dangerous in XSS context: <, >, ", ', /
    _dangerous_codepoints = {60, 62, 34, 39, 47}  # < > " ' /

    for pattern in _PATTERNS_007[:2]:  # hex and decimal entity patterns
        for match in pattern.finditer(value):
            entity = match.group(0)
            # Decode the entity to see if it maps to a dangerous char
            try:
                decoded_char = _decode_html_entity(entity)
                if decoded_char and ord(decoded_char) in _dangerous_codepoints:
                    return XSSFinding(
                        check_id="XSS-007",
                        severity="HIGH",
                        title="HTML Entity / Double-encoded XSS Detected",
                        detail=(
                            "Value contains an HTML entity encoding a dangerous "
                            "character (<, >, \", ', /)."
                        ),
                        weight=_CHECK_WEIGHTS["XSS-007"],
                        parameter=param,
                        evidence=_truncate(entity),
                    )
            except (ValueError, OverflowError):
                pass

    # Double percent-encoding or unicode escape — these are always suspicious
    for pattern in _PATTERNS_007[2:]:  # %25XX and \uXX patterns
        match = pattern.search(value)
        if match:
            return XSSFinding(
                check_id="XSS-007",
                severity="HIGH",
                title="HTML Entity / Double-encoded XSS Detected",
                detail=(
                    "Value contains double percent-encoding or unicode escape "
                    "sequences that may obfuscate XSS payloads."
                ),
                weight=_CHECK_WEIGHTS["XSS-007"],
                parameter=param,
                evidence=_truncate(match.group(0)),
            )

    return None


def _decode_html_entity(entity: str) -> Optional[str]:
    """Decode a single HTML entity like &#60; or &#x3C; to its character."""
    entity = entity.rstrip(";")
    if entity.startswith("&#x") or entity.startswith("&#X"):
        return chr(int(entity[3:], 16))
    if entity.startswith("&#"):
        return chr(int(entity[2:]))
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def evaluate(
    params: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    block_on_severity: str = "CRITICAL",
) -> XSSResult:
    """Evaluate an HTTP request for XSS attack patterns.

    Args:
        params: Query string or POST parameters as key/value pairs.
        headers: HTTP request headers as key/value pairs.
        body: Raw HTTP request body as a string.
        block_on_severity: Minimum severity that sets blocked=True.
            Defaults to "CRITICAL". Use "HIGH" to block on HIGH+ findings.

    Returns:
        XSSResult with all findings, a risk_score (0-100), and a blocked flag.
    """
    pairs = _collect_pairs(params, headers, body)

    all_findings: List[XSSFinding] = []
    fired_check_ids: set = set()

    for param, value in pairs:
        # --- XSS-001 ---
        finding_001 = _check_001(param, value)
        raw_fired_001 = finding_001 is not None
        if finding_001 and finding_001.check_id not in fired_check_ids:
            all_findings.append(finding_001)
            fired_check_ids.add(finding_001.check_id)
        elif finding_001:
            # Still record per-parameter findings even if check already fired
            all_findings.append(finding_001)

        # --- XSS-002 ---
        finding_002 = _check_002(param, value)
        if finding_002:
            all_findings.append(finding_002)

        # --- XSS-003 ---
        finding_003 = _check_003(param, value)
        if finding_003:
            all_findings.append(finding_003)

        # --- XSS-004 ---
        finding_004 = _check_004(param, value)
        raw_fired_004 = finding_004 is not None
        if finding_004:
            all_findings.append(finding_004)

        # --- XSS-005 ---
        finding_005 = _check_005(param, value)
        raw_fired_005 = finding_005 is not None
        if finding_005:
            all_findings.append(finding_005)

        # --- XSS-006 ---
        finding_006 = _check_006(
            param, value, raw_fired_001, raw_fired_004, raw_fired_005
        )
        if finding_006:
            all_findings.append(finding_006)

        # --- XSS-007 ---
        finding_007 = _check_007(param, value)
        if finding_007:
            all_findings.append(finding_007)

    # Deduplicate check IDs for risk scoring
    unique_fired: set = {f.check_id for f in all_findings}
    risk_score = min(100, sum(_CHECK_WEIGHTS[cid] for cid in unique_fired))

    # Determine blocked flag
    blocked = any(
        _severity_gte(f.severity, block_on_severity) for f in all_findings
    )

    return XSSResult(
        findings=all_findings,
        risk_score=risk_score,
        blocked=blocked,
    )


def evaluate_many(requests: List[dict]) -> List[XSSResult]:
    """Evaluate multiple HTTP requests for XSS patterns.

    Args:
        requests: List of request dicts. Each dict may contain optional keys:
            - "params": Dict[str, str] — query/POST parameters
            - "headers": Dict[str, str] — HTTP headers
            - "body": str — raw request body
            - "block_on_severity": str — severity threshold (default "CRITICAL")

    Returns:
        List of XSSResult objects, one per request dict (same order).
    """
    results: List[XSSResult] = []
    for req in requests:
        result = evaluate(
            params=req.get("params"),
            headers=req.get("headers"),
            body=req.get("body"),
            block_on_severity=req.get("block_on_severity", "CRITICAL"),
        )
        results.append(result)
    return results
