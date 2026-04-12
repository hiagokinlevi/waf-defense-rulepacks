# open_redirect_pack.py — WAF rulepack: Open Redirect Detection
#
# Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# Part of Cyber Port portfolio — github.com/hiagokinlevi
# Detects open redirect vulnerabilities in HTTP request parameters:
#   external domain redirects, URL-encoded bypasses, protocol-relative
#   and JavaScript/data URI schemes, and suspicious TLD patterns.

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional
from urllib.parse import unquote, urlparse

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Check weights (used to compute risk_score)
_CHECK_WEIGHTS: Dict[str, int] = {
    "ORED-001": 45,  # Absolute URL redirect to external domain — CRITICAL
    "ORED-002": 25,  # URL-encoded bypass revealing external URL — HIGH
    "ORED-003": 25,  # Double/triple-slash protocol-relative redirect — HIGH
    "ORED-004": 20,  # Backslash-prefixed redirect bypass — HIGH
    "ORED-005": 45,  # JavaScript / VBScript scheme — CRITICAL
    "ORED-006": 30,  # data: URI scheme — HIGH
    "ORED-007": 15,  # Suspicious TLD in redirect URL — MEDIUM
}

# Severity labels for each check
_CHECK_SEVERITY: Dict[str, str] = {
    "ORED-001": "CRITICAL",
    "ORED-002": "HIGH",
    "ORED-003": "HIGH",
    "ORED-004": "HIGH",
    "ORED-005": "CRITICAL",
    "ORED-006": "HIGH",
    "ORED-007": "MEDIUM",
}

# Human-readable titles
_CHECK_TITLES: Dict[str, str] = {
    "ORED-001": "External absolute URL redirect",
    "ORED-002": "URL-encoded redirect bypass",
    "ORED-003": "Protocol-relative redirect (double/triple slash)",
    "ORED-004": "Backslash-prefixed redirect bypass",
    "ORED-005": "JavaScript / VBScript scheme in redirect",
    "ORED-006": "Data URI scheme in redirect",
    "ORED-007": "Suspicious TLD in redirect URL",
}

# Default set of parameter names considered redirect-carrying (case-insensitive)
_DEFAULT_REDIRECT_PARAMS: frozenset = frozenset({
    "url", "redirect", "next", "return", "returnurl", "goto", "dest",
    "location", "back", "callback", "continue", "forward", "target",
    "ref", "redir",
})

# Headers that may carry redirect values
_REDIRECT_HEADERS: frozenset = frozenset({"location", "refresh"})

# TLDs considered suspicious
_SUSPICIOUS_TLDS: frozenset = frozenset({
    ".xyz", ".top", ".tk", ".cc", ".pw", ".ga", ".cf", ".ml", ".gq",
})

# Maximum length of evidence snippets
_MAX_EVIDENCE_LEN: int = 100
_MAX_URL_DECODE_PASSES: int = 3


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class OREDFinding:
    """A single fired detection rule result."""
    check_id: str
    severity: str       # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    weight: int
    parameter: str      # which param triggered it
    evidence: str       # matching portion, truncated to 100 chars


@dataclass
class OREDResult:
    """Aggregated result for one evaluated request."""
    findings: List[OREDFinding] = field(default_factory=list)
    risk_score: int = 0         # min(100, sum of unique fired check weights)
    blocked: bool = False       # True when any CRITICAL finding present

    # ------------------------------------------------------------------
    def to_dict(self) -> dict:
        """Return a JSON-serialisable dict representation."""
        return {
            "risk_score": self.risk_score,
            "blocked": self.blocked,
            "findings": [asdict(f) for f in self.findings],
        }

    def summary(self) -> str:
        """One-line human-readable summary."""
        if not self.findings:
            return "No open redirect findings. Risk score: 0."
        ids = ", ".join(sorted({f.check_id for f in self.findings}))
        return (
            f"Open redirect findings: {len(self.findings)} finding(s) "
            f"[{ids}]. Risk score: {self.risk_score}. "
            f"Blocked: {self.blocked}."
        )

    def by_severity(self) -> dict:
        """Group findings by severity label."""
        groups: Dict[str, List[OREDFinding]] = {}
        for finding in self.findings:
            groups.setdefault(finding.severity, []).append(finding)
        return groups


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _truncate(value: str, max_len: int = _MAX_EVIDENCE_LEN) -> str:
    """Truncate a string for use as evidence, appending '...' if cut."""
    if len(value) <= max_len:
        return value
    return value[:max_len] + "..."


def _extract_domain(url: str) -> str:
    """Return the lowercased hostname from an absolute URL, or '' on failure."""
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _iter_decoded_variants(value: str, max_passes: int = _MAX_URL_DECODE_PASSES) -> List[str]:
    """Return distinct percent-decoded variants in decode order."""
    variants: List[str] = []
    seen: set[str] = set()
    current = value
    for _ in range(max_passes):
        decoded = unquote(current)
        if decoded == current or decoded in seen:
            break
        variants.append(decoded)
        seen.add(decoded)
        current = decoded
    return variants


def _domain_allowed(domain: str, allowed_domains: List[str]) -> bool:
    """Return True when domain matches any entry in allowed_domains (case-insensitive)."""
    if not allowed_domains:
        return False
    lower_domain = domain.lower()
    for allowed in allowed_domains:
        if lower_domain == allowed.lower():
            return True
    return False


def _extract_tld(value: str) -> Optional[str]:
    """
    Attempt to extract the TLD from the first URL-like structure found in value.
    Returns the TLD string (e.g. '.xyz') or None if none found.
    Only considers values that contain '//' or start with 'http'.
    """
    # Quick pre-check: must look URL-like to avoid false positives
    lower = value.lower()
    if "//" not in lower and not lower.startswith("http"):
        return None

    try:
        parsed = urlparse(value if "://" in value else "http:" + value)
        hostname = parsed.hostname or ""
    except Exception:
        hostname = ""

    if not hostname:
        # Fallback: pull hostname portion after //
        match = re.search(r"//([^/?#\s]+)", value)
        if match:
            hostname = match.group(1).split(":")[0]  # strip port

    if not hostname:
        return None

    # Extract the last label
    parts = hostname.rstrip(".").split(".")
    if len(parts) < 2:
        return None
    return "." + parts[-1].lower()


def _is_ored001_pattern(value: str) -> bool:
    """Return True if value looks like an absolute http/https URL."""
    lower = value.lower()
    return lower.startswith("http://") or lower.startswith("https://")


def _run_checks(
    param_name: str,
    raw_value: str,
    allowed_domains: List[str],
) -> List[OREDFinding]:
    """
    Run all ORED checks against a single (param_name, raw_value) pair.
    Returns a list of OREDFinding objects (may be empty).
    """
    findings: List[OREDFinding] = []
    stripped = raw_value.lstrip()       # for checks sensitive to leading whitespace
    fired_001 = False                   # track whether ORED-001 fired
    decoded_variants = _iter_decoded_variants(raw_value)
    decoded_candidates = [variant.lstrip() for variant in decoded_variants]

    def _first_matching_candidate(pattern_check) -> Optional[tuple[str, bool]]:
        if pattern_check(stripped):
            return stripped, False
        for candidate in decoded_candidates:
            if pattern_check(candidate):
                return candidate, True
        return None

    # ------------------------------------------------------------------
    # ORED-001 — Absolute URL redirect to external domain
    # ------------------------------------------------------------------
    if _is_ored001_pattern(stripped):
        domain = _extract_domain(stripped)
        if not _domain_allowed(domain, allowed_domains):
            fired_001 = True
            findings.append(OREDFinding(
                check_id="ORED-001",
                severity=_CHECK_SEVERITY["ORED-001"],
                title=_CHECK_TITLES["ORED-001"],
                detail=(
                    f"Parameter '{param_name}' contains an absolute URL pointing to "
                    f"external domain '{domain}'."
                ),
                weight=_CHECK_WEIGHTS["ORED-001"],
                parameter=param_name,
                evidence=_truncate(stripped),
            ))

    # ------------------------------------------------------------------
    # ORED-002 — URL-encoded bypass
    # ------------------------------------------------------------------
    if not fired_001:
        # Only fire when raw did NOT already trigger ORED-001
        for decoded in decoded_variants:
            if _is_ored001_pattern(decoded.lstrip()):
                domain = _extract_domain(decoded.lstrip())
                if not _domain_allowed(domain, allowed_domains):
                    findings.append(OREDFinding(
                        check_id="ORED-002",
                        severity=_CHECK_SEVERITY["ORED-002"],
                        title=_CHECK_TITLES["ORED-002"],
                        detail=(
                            f"Parameter '{param_name}' URL-encoded value decodes to an "
                            f"external absolute URL (domain: '{domain}')."
                        ),
                        weight=_CHECK_WEIGHTS["ORED-002"],
                        parameter=param_name,
                        evidence=_truncate(raw_value),
                    ))
                break

    # ------------------------------------------------------------------
    # ORED-003 — Double/triple-slash protocol-relative redirect
    # ------------------------------------------------------------------
    ored003_match = _first_matching_candidate(
        lambda value: value.startswith("///") or value.startswith("//")
    )
    if ored003_match:
        evidence, decoded_bypass = ored003_match
        findings.append(OREDFinding(
            check_id="ORED-003",
            severity=_CHECK_SEVERITY["ORED-003"],
            title=_CHECK_TITLES["ORED-003"],
            detail=(
                f"Parameter '{param_name}' "
                + (
                    "URL-encoded value decodes to a protocol-relative redirect "
                    "to an external host."
                    if decoded_bypass
                    else "starts with '//{...}' suggesting a protocol-relative "
                    "redirect to an external host."
                )
            ),
            weight=_CHECK_WEIGHTS["ORED-003"],
            parameter=param_name,
            evidence=_truncate(raw_value if decoded_bypass else evidence),
        ))

    # ------------------------------------------------------------------
    # ORED-004 — Backslash bypass
    # ------------------------------------------------------------------
    # Matches: \, \\, /\, \/  at start of (stripped) value
    ored004_match = _first_matching_candidate(
        lambda value: bool(re.match(r"^(\\\\|\\|/\\|\\/)", value))
    )
    if ored004_match:
        evidence, decoded_bypass = ored004_match
        findings.append(OREDFinding(
            check_id="ORED-004",
            severity=_CHECK_SEVERITY["ORED-004"],
            title=_CHECK_TITLES["ORED-004"],
            detail=(
                f"Parameter '{param_name}' "
                + (
                    "URL-encoded value decodes to a backslash-prefixed redirect "
                    "bypass sequence."
                    if decoded_bypass
                    else "starts with a backslash sequence, a common "
                    "path-normalisation bypass technique."
                )
            ),
            weight=_CHECK_WEIGHTS["ORED-004"],
            parameter=param_name,
            evidence=_truncate(raw_value if decoded_bypass else evidence),
        ))

    # ------------------------------------------------------------------
    # ORED-005 — javascript: / vbscript: scheme
    # ------------------------------------------------------------------
    ored005_match = _first_matching_candidate(
        lambda value: bool(re.match(r"^(javascript|vbscript)\s*:", value, re.IGNORECASE))
    )
    if ored005_match:
        evidence, decoded_bypass = ored005_match
        findings.append(OREDFinding(
            check_id="ORED-005",
            severity=_CHECK_SEVERITY["ORED-005"],
            title=_CHECK_TITLES["ORED-005"],
            detail=(
                f"Parameter '{param_name}' "
                + (
                    "URL-encoded value decodes to a JavaScript or VBScript URI "
                    "scheme that can execute arbitrary code in the browser."
                    if decoded_bypass
                    else "contains a JavaScript or VBScript URI scheme — can "
                    "execute arbitrary code in the browser."
                )
            ),
            weight=_CHECK_WEIGHTS["ORED-005"],
            parameter=param_name,
            evidence=_truncate(raw_value if decoded_bypass else evidence),
        ))

    # ------------------------------------------------------------------
    # ORED-006 — data: URI scheme
    # ------------------------------------------------------------------
    ored006_match = _first_matching_candidate(lambda value: value.lower().startswith("data:"))
    if ored006_match:
        evidence, decoded_bypass = ored006_match
        findings.append(OREDFinding(
            check_id="ORED-006",
            severity=_CHECK_SEVERITY["ORED-006"],
            title=_CHECK_TITLES["ORED-006"],
            detail=(
                f"Parameter '{param_name}' "
                + (
                    "URL-encoded value decodes to a data: URI, which can embed "
                    "arbitrary HTML/JavaScript payloads."
                    if decoded_bypass
                    else "contains a data: URI, which can embed arbitrary "
                    "HTML/JavaScript payloads."
                )
            ),
            weight=_CHECK_WEIGHTS["ORED-006"],
            parameter=param_name,
            evidence=_truncate(raw_value if decoded_bypass else evidence),
        ))

    # ------------------------------------------------------------------
    # ORED-007 — Suspicious TLD
    # ------------------------------------------------------------------
    # Only fire when raw or decoded value is URL-like and the destination is not allow-listed.
    for candidate in [stripped, *decoded_candidates]:
        lower_val = candidate.lower()
        if "//" not in lower_val and not lower_val.startswith("http"):
            continue
        tld = _extract_tld(candidate)
        if not tld or tld not in _SUSPICIOUS_TLDS:
            continue
        domain = _extract_domain(candidate if "://" in candidate else "http:" + candidate)
        if _domain_allowed(domain, allowed_domains):
            continue
        findings.append(OREDFinding(
            check_id="ORED-007",
            severity=_CHECK_SEVERITY["ORED-007"],
            title=_CHECK_TITLES["ORED-007"],
            detail=(
                f"Parameter '{param_name}' redirect URL uses suspicious TLD "
                f"'{tld}', commonly associated with malicious domains."
            ),
            weight=_CHECK_WEIGHTS["ORED-007"],
            parameter=param_name,
            evidence=_truncate(raw_value if candidate != stripped else candidate),
        ))
        break

    return findings


def _build_result(
    findings: List[OREDFinding],
    block_on_severity: str,
) -> OREDResult:
    """Compute risk_score and blocked flag from a list of findings."""
    # Deduplicate by check_id for weight accumulation
    fired_ids: set = set()
    total_weight = 0
    for finding in findings:
        if finding.check_id not in fired_ids:
            fired_ids.add(finding.check_id)
            total_weight += finding.weight

    risk_score = min(100, total_weight)

    # Determine severity order for blocking
    _SEV_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    threshold = _SEV_ORDER.get(block_on_severity.upper(), 4)
    blocked = any(
        _SEV_ORDER.get(f.severity.upper(), 0) >= threshold
        for f in findings
    )

    return OREDResult(
        findings=findings,
        risk_score=risk_score,
        blocked=blocked,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def evaluate(
    params: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    redirect_param_names: Optional[List[str]] = None,
    allowed_domains: Optional[List[str]] = None,
    block_on_severity: str = "CRITICAL",
) -> OREDResult:
    """
    Evaluate HTTP request data for open redirect vulnerabilities.

    Parameters
    ----------
    params:
        Query-string / form parameters as a plain dict.
    headers:
        HTTP request/response headers as a plain dict.
    body:
        Raw request body string.
    redirect_param_names:
        Explicit list of parameter names to inspect. When None, the module
        checks every param whose lowercased name is in _DEFAULT_REDIRECT_PARAMS.
    allowed_domains:
        Domains that are considered safe destinations (not flagged by ORED-001
        or ORED-002 / ORED-007).
    block_on_severity:
        Minimum severity level that sets OREDResult.blocked = True.
        Defaults to "CRITICAL".

    Returns
    -------
    OREDResult
    """
    params = params or {}
    headers = headers or {}
    allowed_domains = allowed_domains or []

    # Build the effective set of param names to inspect
    if redirect_param_names is not None:
        effective_names: frozenset = frozenset(n.lower() for n in redirect_param_names)
    else:
        effective_names = _DEFAULT_REDIRECT_PARAMS

    all_findings: List[OREDFinding] = []

    # --- Query / form parameters ---
    for raw_name, value in params.items():
        if raw_name.lower() in effective_names:
            all_findings.extend(_run_checks(raw_name, value, allowed_domains))

    # --- Headers (only Location and Refresh) ---
    for raw_name, value in headers.items():
        if raw_name.lower() in _REDIRECT_HEADERS:
            all_findings.extend(_run_checks(raw_name, value, allowed_domains))

    # --- Body (treated as a single opaque value) ---
    if body is not None:
        all_findings.extend(_run_checks("body", body, allowed_domains))

    return _build_result(all_findings, block_on_severity)


def evaluate_many(requests: List[dict]) -> List[OREDResult]:
    """
    Evaluate a batch of requests.

    Each request dict may contain the optional keys:
        params, headers, body, redirect_param_names, allowed_domains,
        block_on_severity.

    Returns a list of OREDResult objects in the same order as the input.
    """
    results: List[OREDResult] = []
    for req in requests:
        results.append(evaluate(
            params=req.get("params"),
            headers=req.get("headers"),
            body=req.get("body"),
            redirect_param_names=req.get("redirect_param_names"),
            allowed_domains=req.get("allowed_domains"),
            block_on_severity=req.get("block_on_severity", "CRITICAL"),
        ))
    return results
