# SPDX-License-Identifier: CC-BY-4.0
# Creative Commons Attribution 4.0 International License
# https://creativecommons.org/licenses/by/4.0/
#
# Cyber Port — WAF Defense Rulepacks
# Module  : command_injection_pack.py
# Purpose : Detect OS command injection patterns in HTTP request parameters.
# Stdlib  : re, urllib.parse (no third-party dependencies)
# Compat  : Python 3.9+

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Check weight table — risk_score = min(100, sum of weights for unique fired IDs)
# ---------------------------------------------------------------------------
_CHECK_WEIGHTS: Dict[str, int] = {
    "CMD-001": 45,  # Shell metacharacters           (CRITICAL)
    "CMD-002": 45,  # Command substitution operators  (CRITICAL)
    "CMD-003": 30,  # Newline / carriage return        (HIGH)
    "CMD-004": 25,  # File redirection operators       (HIGH)
    "CMD-005": 45,  # Known dangerous OS commands      (CRITICAL)
    "CMD-006": 30,  # URL-encoded injection chars      (HIGH)
    "CMD-007": 25,  # Null byte / special escape       (HIGH)
}

# Severity labels for each check ID
_CHECK_SEVERITY: Dict[str, str] = {
    "CMD-001": "CRITICAL",
    "CMD-002": "CRITICAL",
    "CMD-003": "HIGH",
    "CMD-004": "HIGH",
    "CMD-005": "CRITICAL",
    "CMD-006": "HIGH",
    "CMD-007": "HIGH",
}

# Blocking threshold ordering — severities considered >= a given level
_SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class HTTPRequest:
    """Represents an incoming HTTP request to be evaluated by the WAF rulepack."""

    url: str
    method: str = "GET"
    query_params: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialise the request to a plain dictionary."""
        return {
            "url": self.url,
            "method": self.method,
            "query_params": self.query_params,
            "body": self.body,
            "headers": self.headers,
        }


@dataclass
class CMDFinding:
    """A single command-injection finding raised against one value."""

    check_id: str           # e.g. "CMD-001"
    severity: str           # e.g. "CRITICAL"
    rule_name: str          # human-readable name of the rule
    matched_value: str      # first 100 chars of the offending value
    param_location: str     # e.g. "query_params", "body", "headers"
    recommendation: str     # remediation guidance

    def to_dict(self) -> dict:
        """Serialise the finding to a plain dictionary."""
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "rule_name": self.rule_name,
            "matched_value": self.matched_value,
            "param_location": self.param_location,
            "recommendation": self.recommendation,
        }


@dataclass
class CMDEvalResult:
    """Aggregate result of evaluating one HTTPRequest against all CMD checks."""

    findings: List[CMDFinding] = field(default_factory=list)
    risk_score: int = 0      # 0–100
    blocked: bool = False

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Return a one-line human-readable summary of the evaluation result."""
        if not self.findings:
            return "PASS — no command injection patterns detected (risk_score=0)"
        check_ids = ", ".join(sorted({f.check_id for f in self.findings}))
        action = "BLOCKED" if self.blocked else "FLAGGED"
        return (
            f"{action} — {len(self.findings)} finding(s) across checks [{check_ids}]; "
            f"risk_score={self.risk_score}"
        )

    def by_severity(self) -> Dict[str, List[CMDFinding]]:
        """Group findings by severity label."""
        groups: Dict[str, List[CMDFinding]] = {}
        for finding in self.findings:
            groups.setdefault(finding.severity, []).append(finding)
        return groups

    def to_dict(self) -> dict:
        """Serialise the evaluation result to a plain dictionary."""
        return {
            "findings": [f.to_dict() for f in self.findings],
            "risk_score": self.risk_score,
            "blocked": self.blocked,
            "summary": self.summary(),
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_values(request: HTTPRequest) -> List[Tuple[str, str]]:
    """Return (value, location) pairs from all inspectable request surfaces.

    Surfaces inspected:
      * query_params  — each dict value
      * body          — the raw body string (if present)
      * headers       — each dict value (keys are skipped; header names are
                        well-defined and should not carry user-controlled data)
    """
    pairs: List[Tuple[str, str]] = []

    # Query parameters
    for v in request.query_params.values():
        pairs.append((str(v), "query_params"))

    # Body
    if request.body is not None:
        pairs.append((request.body, "body"))

    # Header values
    for v in request.headers.values():
        pairs.append((str(v), "headers"))

    return pairs


# Compile reusable patterns once at module load time for performance
_RE_CMD001 = re.compile(r'[;|]|&&|\|\|')
_RE_CMD002 = re.compile(r'`|\$\(|\$\{[A-Z_]+\}|\$[0-9]')
_RE_CMD003 = re.compile(r'\n|\r|%0[aAdD]')
_RE_CMD004 = re.compile(r'>>?|2>&1|[12]>')
_RE_CMD005 = re.compile(
    r'\b(cat|wget|curl|bash|sh|nc|netcat|python|perl|ruby|php|chmod|chown|'
    r'rm|mv|cp|dd|mkfifo|socat|ncat|nmap|masscan|tcpdump|base64|xxd|od)\b',
    re.IGNORECASE,
)
_RE_CMD007 = re.compile(r'%00|\x00|%09')

# Patterns used to check whether decoded content reveals injection chars
# (used by CMD-006 to decide if URL-decoding exposes new threats)
_RE_CMD006_REVEAL = re.compile(r'[;|`]|\$\(')


# ---------------------------------------------------------------------------
# Recommendation strings per check ID
# ---------------------------------------------------------------------------
_RECOMMENDATIONS: Dict[str, str] = {
    "CMD-001": (
        "Strip or reject shell metacharacters (;, |, &&, ||) from all "
        "user-supplied inputs. Use parameterised APIs instead of shell invocation."
    ),
    "CMD-002": (
        "Block backtick and $() substitution syntax. Avoid passing user data to "
        "any shell interpreter. Use subprocess with argument lists, not shell=True."
    ),
    "CMD-003": (
        "Reject or encode newline (\\n, \\r) and their percent-encoded equivalents "
        "in all inputs. Newlines can inject additional commands or log entries."
    ),
    "CMD-004": (
        "Remove file redirection operators (>, >>, <, 2>&1) from user inputs. "
        "Never construct shell commands that include untrusted data."
    ),
    "CMD-005": (
        "Block known shell command names at word boundaries in user input. "
        "Apply a strict allowlist for expected input values."
    ),
    "CMD-006": (
        "Apply URL-decoding before validation so that percent-encoded injection "
        "sequences are caught. Decode first, validate second."
    ),
    "CMD-007": (
        "Reject null bytes (%00, \\x00) and suspicious whitespace sequences (%09) "
        "in all inputs; these can bypass naive string filters."
    ),
}

_RULE_NAMES: Dict[str, str] = {
    "CMD-001": "Shell Metacharacter Injection",
    "CMD-002": "Command Substitution Operator Injection",
    "CMD-003": "Newline / Carriage Return Injection",
    "CMD-004": "File Redirection Operator Injection",
    "CMD-005": "Known Dangerous OS Command in Input",
    "CMD-006": "URL-Encoded Command Injection Characters",
    "CMD-007": "Null Byte / Special Escape Injection",
}


# ---------------------------------------------------------------------------
# Main rulepack class
# ---------------------------------------------------------------------------

class CommandInjectionPack:
    """WAF rulepack that detects OS command injection patterns (CMD-001 – CMD-007).

    Args:
        block_on_severity: The minimum severity at which the request should be
            marked ``blocked=True``.  Accepted values (case-insensitive):
            ``"LOW"``, ``"MEDIUM"``, ``"HIGH"``, ``"CRITICAL"``.
            Defaults to ``"HIGH"``.
    """

    def __init__(self, block_on_severity: str = "HIGH") -> None:
        severity_upper = block_on_severity.upper()
        if severity_upper not in _SEVERITY_ORDER:
            raise ValueError(
                f"block_on_severity must be one of {_SEVERITY_ORDER}, "
                f"got {block_on_severity!r}"
            )
        self.block_on_severity = severity_upper

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, request: HTTPRequest) -> CMDEvalResult:
        """Evaluate a single HTTP request against all CMD checks.

        Returns:
            CMDEvalResult with findings, risk_score, and blocked flag.
        """
        findings: List[CMDFinding] = []
        fired_ids: set = set()  # track unique check IDs to avoid double-weight

        value_pairs = _extract_values(request)

        for value, location in value_pairs:
            # ----------------------------------------------------------
            # CMD-001 — Shell metacharacters
            # ----------------------------------------------------------
            if _RE_CMD001.search(value):
                findings.append(self._make_finding("CMD-001", value, location))
                fired_ids.add("CMD-001")

            # ----------------------------------------------------------
            # CMD-002 — Command substitution operators
            # ----------------------------------------------------------
            if _RE_CMD002.search(value):
                findings.append(self._make_finding("CMD-002", value, location))
                fired_ids.add("CMD-002")

            # ----------------------------------------------------------
            # CMD-003 — Newline / carriage return injection
            # ----------------------------------------------------------
            if _RE_CMD003.search(value):
                findings.append(self._make_finding("CMD-003", value, location))
                fired_ids.add("CMD-003")

            # ----------------------------------------------------------
            # CMD-004 — File redirection operators
            # ----------------------------------------------------------
            if _RE_CMD004.search(value):
                findings.append(self._make_finding("CMD-004", value, location))
                fired_ids.add("CMD-004")

            # ----------------------------------------------------------
            # CMD-005 — Known dangerous OS commands
            # ----------------------------------------------------------
            if _RE_CMD005.search(value):
                findings.append(self._make_finding("CMD-005", value, location))
                fired_ids.add("CMD-005")

            # ----------------------------------------------------------
            # CMD-006 — URL-encoded command injection characters
            # URL-decode the value; if decoding exposes injection chars
            # that were NOT already present in the raw value, raise CMD-006.
            # CMD-001/CMD-002 are NOT raised again to avoid double-counting.
            # ----------------------------------------------------------
            decoded = urllib.parse.unquote(value)
            if decoded != value:
                # Only flag CMD-006 if the decoded form reveals new threats
                raw_has_injection = bool(_RE_CMD006_REVEAL.search(value))
                decoded_has_injection = bool(_RE_CMD006_REVEAL.search(decoded))
                if decoded_has_injection and not raw_has_injection:
                    findings.append(self._make_finding("CMD-006", value, location))
                    fired_ids.add("CMD-006")

            # ----------------------------------------------------------
            # CMD-007 — Null byte / special escape injection
            # ----------------------------------------------------------
            if _RE_CMD007.search(value):
                findings.append(self._make_finding("CMD-007", value, location))
                fired_ids.add("CMD-007")

        # Compute risk_score from unique fired check IDs (cap at 100)
        risk_score = min(100, sum(_CHECK_WEIGHTS[cid] for cid in fired_ids))

        # Determine if the request should be blocked
        blocked = self._should_block(findings)

        return CMDEvalResult(
            findings=findings,
            risk_score=risk_score,
            blocked=blocked,
        )

    def evaluate_many(self, requests: List[HTTPRequest]) -> List[CMDEvalResult]:
        """Evaluate a list of HTTP requests, returning one result per request.

        Args:
            requests: Sequence of HTTPRequest objects to evaluate.

        Returns:
            List of CMDEvalResult in the same order as the input list.
        """
        return [self.evaluate(req) for req in requests]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_finding(
        self, check_id: str, value: str, location: str
    ) -> CMDFinding:
        """Construct a CMDFinding for a triggered check."""
        return CMDFinding(
            check_id=check_id,
            severity=_CHECK_SEVERITY[check_id],
            rule_name=_RULE_NAMES[check_id],
            matched_value=value[:100],   # truncate to first 100 chars
            param_location=location,
            recommendation=_RECOMMENDATIONS[check_id],
        )

    def _should_block(self, findings: List[CMDFinding]) -> bool:
        """Return True if any finding meets or exceeds the block threshold."""
        block_index = _SEVERITY_ORDER.index(self.block_on_severity)
        for finding in findings:
            sev_index = _SEVERITY_ORDER.index(finding.severity)
            if sev_index >= block_index:
                return True
        return False
