# CC BY 4.0 License — Cyber Port Portfolio
# https://creativecommons.org/licenses/by/4.0/
#
# Module: sqli_detection_pack.py
# Purpose: WAF rulepack — detects SQL injection attempts in HTTP request
#          parameters, headers, and body via regex pattern matching.
# Repo: k1N-WAF-Defense-Rulepacks
# Compatible: Python 3.9+

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Severity ordering (higher index = higher severity)
# ---------------------------------------------------------------------------
_SEVERITY_ORDER: Dict[str, int] = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# ---------------------------------------------------------------------------
# Check weights
# ---------------------------------------------------------------------------
_CHECK_WEIGHTS: Dict[str, int] = {
    "SQLI-001": 45,  # Classic SQL injection
    "SQLI-002": 45,  # Time-based blind SQLi
    "SQLI-003": 30,  # Boolean-based blind SQLi
    "SQLI-004": 30,  # Error-based SQLi
    "SQLI-005": 45,  # Stacked queries
    "SQLI-006": 25,  # URL-encoded bypass
    "SQLI-007": 25,  # Comment-based obfuscation
}

# ---------------------------------------------------------------------------
# Check metadata (id -> (severity, title))
# ---------------------------------------------------------------------------
_CHECK_META: Dict[str, Tuple[str, str]] = {
    "SQLI-001": ("CRITICAL", "Classic SQL Injection"),
    "SQLI-002": ("CRITICAL", "Time-Based Blind SQL Injection"),
    "SQLI-003": ("HIGH",     "Boolean-Based Blind SQL Injection"),
    "SQLI-004": ("HIGH",     "Error-Based SQL Injection"),
    "SQLI-005": ("CRITICAL", "Stacked Queries SQL Injection"),
    "SQLI-006": ("HIGH",     "URL-Encoded SQL Injection Bypass"),
    "SQLI-007": ("HIGH",     "Comment-Based SQL Injection Obfuscation"),
}

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# SQLI-001: Classic — UNION SELECT, OR/AND equality tricks.
# The OR/AND patterns match both numeric (1=1) and quoted-string ('a'='a)
# equality comparisons.  The trailing quote is optional because real SQL
# injection payloads often omit the closing quote (e.g., ' OR 'a'='a).
_PATTERNS_001: List[re.Pattern] = [
    re.compile(r"UNION\s+(?:ALL\s+)?SELECT", re.IGNORECASE),
    re.compile(r"\bOR\b\s+(?:'[^']*'?|\d+)\s*=\s*(?:'[^']*'?|\d+)", re.IGNORECASE),
    re.compile(r"\bAND\b\s+(?:'[^']*'?|\d+)\s*=\s*(?:'[^']*'?|\d+)", re.IGNORECASE),
]

# SQLI-002: Time-based blind
_PATTERNS_002: List[re.Pattern] = [
    re.compile(r"SLEEP\s*\(", re.IGNORECASE),
    re.compile(r"WAITFOR\s+DELAY", re.IGNORECASE),
    re.compile(r"BENCHMARK\s*\(", re.IGNORECASE),
    re.compile(r"pg_sleep\s*\(", re.IGNORECASE),
]

# SQLI-003: Boolean-based blind
_PATTERNS_003: List[re.Pattern] = [
    re.compile(r"AND\s+\d+=\d+", re.IGNORECASE),
    re.compile(r"AND\s+'[^']*'\s*=\s*'[^']*'", re.IGNORECASE),
    re.compile(r"'\s+OR\s+'\w+'", re.IGNORECASE),
]

# SQLI-004: Error-based
_PATTERNS_004: List[re.Pattern] = [
    re.compile(r"EXTRACTVALUE\s*\(", re.IGNORECASE),
    re.compile(r"UPDATEXML\s*\(", re.IGNORECASE),
    re.compile(r"FLOOR\s*\(\s*RAND\s*\(", re.IGNORECASE),
    re.compile(r"EXP\s*\(\s*~", re.IGNORECASE),
    re.compile(r"GeometryCollection\s*\(", re.IGNORECASE),
]

# SQLI-005: Stacked queries
_PATTERNS_005: List[re.Pattern] = [
    re.compile(r";\s*(?:INSERT|DROP|UPDATE|SELECT|EXEC|CALL)\b", re.IGNORECASE),
]

# SQLI-007: Comment-based obfuscation adjacent to SQL keywords.
# Matches comment token before or after an SQL keyword (within the same
# broad expression — whitespace/any chars bridging them up to ~20 chars).
_PATTERNS_007: List[re.Pattern] = [
    # comment -> keyword
    re.compile(
        r"(?:/\*\*/|--|#).{0,20}(?:SELECT|INSERT|UPDATE|DELETE|UNION|WHERE|FROM|TABLE|DROP)",
        re.IGNORECASE,
    ),
    # keyword -> comment
    re.compile(
        r"(?:SELECT|INSERT|UPDATE|DELETE|UNION|WHERE|FROM|TABLE|DROP).{0,20}(?:/\*\*/|--|#)",
        re.IGNORECASE,
    ),
]

# Grouped for convenience in the URL-decode check
_ALL_PATTERN_GROUPS: List[Tuple[str, List[re.Pattern]]] = [
    ("SQLI-001", _PATTERNS_001),
    ("SQLI-002", _PATTERNS_002),
    ("SQLI-003", _PATTERNS_003),
    ("SQLI-004", _PATTERNS_004),
    ("SQLI-005", _PATTERNS_005),
]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class SQLIFinding:
    """Represents a single SQLi detection hit."""
    check_id: str
    severity: str    # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    weight: int
    parameter: str   # name of the param / header that triggered the finding
    evidence: str    # matching portion, truncated to 100 chars


@dataclass
class SQLIResult:
    """Aggregated result returned by evaluate()."""
    findings: List[SQLIFinding] = field(default_factory=list)
    risk_score: int = 0
    blocked: bool = False

    def to_dict(self) -> dict:
        """Serialise to a plain dictionary (JSON-friendly)."""
        return {
            "risk_score": self.risk_score,
            "blocked": self.blocked,
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
        }

    def summary(self) -> str:
        """Return a one-line human-readable summary."""
        if not self.findings:
            return "No SQL injection patterns detected. Risk score: 0."
        ids = ", ".join(sorted({f.check_id for f in self.findings}))
        status = "BLOCKED" if self.blocked else "FLAGGED"
        return (
            f"{status} | risk_score={self.risk_score} | "
            f"checks_fired=[{ids}] | findings={len(self.findings)}"
        )

    def by_severity(self) -> Dict[str, List[SQLIFinding]]:
        """Return findings grouped by severity label."""
        groups: Dict[str, List[SQLIFinding]] = {}
        for f in self.findings:
            groups.setdefault(f.severity, []).append(f)
        return groups


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _first_match(patterns: List[re.Pattern], value: str) -> Optional[str]:
    """Return the matched string for the first pattern that hits, else None."""
    for pat in patterns:
        m = pat.search(value)
        if m:
            return m.group(0)
    return None


def _truncate(text: str, max_len: int = 100) -> str:
    """Truncate evidence string to max_len characters."""
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."


def _make_finding(
    check_id: str,
    parameter: str,
    evidence_raw: str,
    detail: str,
) -> SQLIFinding:
    """Construct a SQLIFinding from check metadata and raw evidence."""
    severity, title = _CHECK_META[check_id]
    return SQLIFinding(
        check_id=check_id,
        severity=severity,
        title=title,
        detail=detail,
        weight=_CHECK_WEIGHTS[check_id],
        parameter=parameter,
        evidence=_truncate(evidence_raw),
    )


def _collect_pairs(
    params: Optional[Dict[str, str]],
    headers: Optional[Dict[str, str]],
    body: Optional[str],
) -> List[Tuple[str, str]]:
    """Return (name, value) pairs from all input sources."""
    pairs: List[Tuple[str, str]] = []

    if params:
        for k, v in params.items():
            pairs.append((f"param:{k}", str(v)))

    if headers:
        for k, v in headers.items():
            pairs.append((f"header:{k}", str(v)))

    if body is not None:
        pairs.append(("body", body))

    return pairs


def _severity_gte(sev_a: str, sev_b: str) -> bool:
    """Return True when sev_a >= sev_b in severity ordering."""
    return _SEVERITY_ORDER.get(sev_a, 0) >= _SEVERITY_ORDER.get(sev_b, 0)


# ---------------------------------------------------------------------------
# Per-value check functions
# ---------------------------------------------------------------------------

def _check_value(
    parameter: str,
    value: str,
    findings: List[SQLIFinding],
) -> None:
    """
    Run all SQLI checks against a single (parameter, value) pair and append
    any SQLIFinding objects to the provided list.
    """
    fired_check_ids: List[str] = []  # track which checks already fired THIS value

    # --- SQLI-001 ---
    evidence = _first_match(_PATTERNS_001, value)
    if evidence:
        findings.append(_make_finding(
            "SQLI-001", parameter, evidence,
            "Classic SQL injection pattern detected (UNION SELECT or equality bypass).",
        ))
        fired_check_ids.append("SQLI-001")

    # --- SQLI-002 ---
    evidence = _first_match(_PATTERNS_002, value)
    if evidence:
        findings.append(_make_finding(
            "SQLI-002", parameter, evidence,
            "Time-based blind SQL injection function detected.",
        ))
        fired_check_ids.append("SQLI-002")

    # --- SQLI-003 (skip if SQLI-001 already fired for this value) ---
    if "SQLI-001" not in fired_check_ids:
        evidence = _first_match(_PATTERNS_003, value)
        if evidence:
            findings.append(_make_finding(
                "SQLI-003", parameter, evidence,
                "Boolean-based blind SQL injection pattern detected.",
            ))
            fired_check_ids.append("SQLI-003")

    # --- SQLI-004 ---
    evidence = _first_match(_PATTERNS_004, value)
    if evidence:
        findings.append(_make_finding(
            "SQLI-004", parameter, evidence,
            "Error-based SQL injection function detected.",
        ))
        fired_check_ids.append("SQLI-004")

    # --- SQLI-005 ---
    evidence = _first_match(_PATTERNS_005, value)
    if evidence:
        findings.append(_make_finding(
            "SQLI-005", parameter, evidence,
            "Stacked query SQL injection pattern detected.",
        ))
        fired_check_ids.append("SQLI-005")

    # --- SQLI-006: URL-encoded bypass ---
    # Decode; only fire if decoded differs from raw AND decoded triggers
    # any of SQLI-001 through SQLI-005, AND the raw form did NOT already fire.
    _raw_fired = set(fired_check_ids) & {"SQLI-001", "SQLI-002", "SQLI-003", "SQLI-004", "SQLI-005"}
    decoded = urllib.parse.unquote(value)
    if decoded != value and not _raw_fired:
        for check_id, patterns in _ALL_PATTERN_GROUPS:
            ev = _first_match(patterns, decoded)
            if ev:
                # SQLI-003 skip rule also applies to the decoded form
                if check_id == "SQLI-003":
                    # Check whether SQLI-001 would also fire on decoded
                    if _first_match(_PATTERNS_001, decoded):
                        continue
                findings.append(_make_finding(
                    "SQLI-006", parameter, ev,
                    f"URL-encoded SQL injection bypass detected (decoded form triggers {check_id}).",
                ))
                fired_check_ids.append("SQLI-006")
                break  # one SQLI-006 finding per value is enough

    # --- SQLI-007: Comment-based obfuscation ---
    evidence = _first_match(_PATTERNS_007, value)
    if evidence:
        findings.append(_make_finding(
            "SQLI-007", parameter, evidence,
            "SQL comment-based obfuscation adjacent to SQL keyword detected.",
        ))
        fired_check_ids.append("SQLI-007")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def evaluate(
    params: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    block_on_severity: str = "CRITICAL",
) -> SQLIResult:
    """
    Evaluate an HTTP request for SQL injection attempts.

    Parameters
    ----------
    params:
        URL query parameters or HTML form fields as name->value mapping.
    headers:
        HTTP request headers as name->value mapping.
    body:
        Raw request body string.
    block_on_severity:
        Minimum severity that sets blocked=True on the result.
        Defaults to "CRITICAL". Accepts INFO / LOW / MEDIUM / HIGH / CRITICAL.

    Returns
    -------
    SQLIResult
        Aggregated findings, risk_score (0-100), and blocked flag.
    """
    pairs = _collect_pairs(params, headers, body)
    all_findings: List[SQLIFinding] = []

    for param_name, value in pairs:
        _check_value(param_name, value, all_findings)

    # Deduplicate by check_id for risk score calculation
    fired_ids = {f.check_id for f in all_findings}
    risk_score = min(100, sum(_CHECK_WEIGHTS[cid] for cid in fired_ids))

    # Determine blocked status
    blocked = any(
        _severity_gte(f.severity, block_on_severity) for f in all_findings
    )

    return SQLIResult(
        findings=all_findings,
        risk_score=risk_score,
        blocked=blocked,
    )


def evaluate_many(requests: List[dict]) -> List[SQLIResult]:
    """
    Evaluate a batch of HTTP requests for SQL injection attempts.

    Each request dict may contain the following optional keys:
        params            -- dict[str, str]
        headers           -- dict[str, str]
        body              -- str
        block_on_severity -- str (default "CRITICAL")

    Returns a list of SQLIResult objects in the same order as the input.
    """
    results: List[SQLIResult] = []
    for req in requests:
        results.append(
            evaluate(
                params=req.get("params"),
                headers=req.get("headers"),
                body=req.get("body"),
                block_on_severity=req.get("block_on_severity", "CRITICAL"),
            )
        )
    return results
