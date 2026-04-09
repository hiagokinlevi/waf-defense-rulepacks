# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) 2026 Hiago Kin Levi
"""
Host Header Attack Detection Pack
=================================
Detects host header poisoning and routing override attempts in inbound HTTP
requests. The evaluator is dependency-free and suitable for local WAF rule
development, CI sanity checks, and pre-production traffic fixture review.

Rule Catalogue
--------------
HHO-001  Conflicting host-routing headers present                      (HIGH)
HHO-002  Host-style header contains an absolute URL or scheme          (HIGH)
HHO-003  Host-style header points to loopback/private/metadata target  (CRITICAL)
HHO-004  Host-style header contains invalid characters or traversal    (CRITICAL)
HHO-005  Host / X-Forwarded-Host mismatch across external domains      (HIGH)
HHO-006  Multiple host values supplied in a single header              (HIGH)
HHO-007  Host-style header uses an IP literal where canonical host is a domain (MEDIUM)
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional
from urllib.parse import urlparse

_SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

_CHECK_WEIGHTS: Dict[str, int] = {
    "HHO-001": 30,
    "HHO-002": 25,
    "HHO-003": 45,
    "HHO-004": 45,
    "HHO-005": 25,
    "HHO-006": 20,
    "HHO-007": 15,
}

_CHECK_SEVERITIES: Dict[str, str] = {
    "HHO-001": "HIGH",
    "HHO-002": "HIGH",
    "HHO-003": "CRITICAL",
    "HHO-004": "CRITICAL",
    "HHO-005": "HIGH",
    "HHO-006": "HIGH",
    "HHO-007": "MEDIUM",
}

_CHECK_TITLES: Dict[str, str] = {
    "HHO-001": "Conflicting host-routing headers",
    "HHO-002": "Absolute URL or scheme in host header",
    "HHO-003": "Internal or metadata target in host header",
    "HHO-004": "Invalid characters or traversal in host header",
    "HHO-005": "External host mismatch across forwarding headers",
    "HHO-006": "Multiple host values in a single header",
    "HHO-007": "IP literal override against canonical domain",
}

_HOST_HEADERS: tuple[str, ...] = (
    "host",
    "x-forwarded-host",
    "x-original-host",
    "x-host",
    "forwarded",
)

_INVALID_HOST_RE = re.compile(r"[\s\r\n\t/\\\\]|\.{2,}|[%]")
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+\-.]*://", re.IGNORECASE)
_FORWARDED_HOST_RE = re.compile(r"host=([^;,\s]+)", re.IGNORECASE)
_MAX_EVIDENCE_LEN = 120

_METADATA_IPS = (
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("100.100.100.200"),
)
_METADATA_HOSTS = frozenset({
    "metadata.google.internal",
    "metadata.azure.internal",
    "instance-data.ec2.internal",
})


@dataclass
class HostHeaderRequest:
    """Simplified HTTP request model used by the host header pack."""

    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    method: str = "GET"
    path: str = "/"


@dataclass
class HostHeaderFinding:
    """One host header attack detection finding."""

    check_id: str
    severity: str
    title: str
    detail: str
    header_name: str
    evidence: str
    recommendation: str

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "header_name": self.header_name,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }


@dataclass
class HostHeaderEvalResult:
    """Aggregated evaluation result for a single request."""

    findings: List[HostHeaderFinding]
    risk_score: int
    blocked: bool

    def by_severity(self) -> Dict[str, List[HostHeaderFinding]]:
        groups: Dict[str, List[HostHeaderFinding]] = {}
        for finding in self.findings:
            groups.setdefault(finding.severity, []).append(finding)
        return dict(
            sorted(
                groups.items(),
                key=lambda kv: _SEVERITY_ORDER.get(kv[0], 0),
                reverse=True,
            )
        )

    def summary(self) -> str:
        action = "BLOCKED" if self.blocked else "ALLOWED"
        ids = ",".join(sorted({finding.check_id for finding in self.findings})) or "none"
        return f"[{action}] risk_score={self.risk_score}/100 findings={len(self.findings)} ids={ids}"

    def to_dict(self) -> dict:
        return {
            "findings": [finding.to_dict() for finding in self.findings],
            "risk_score": self.risk_score,
            "blocked": self.blocked,
            "summary": self.summary(),
        }


def _truncate(value: str) -> str:
    if len(value) <= _MAX_EVIDENCE_LEN:
        return value
    return value[:_MAX_EVIDENCE_LEN] + "..."


def _normalise_headers(headers: Dict[str, str]) -> Dict[str, str]:
    return {str(name).lower(): str(value) for name, value in headers.items()}


def _canonical_host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _extract_header_values(headers: Dict[str, str]) -> Dict[str, str]:
    extracted: Dict[str, str] = {}
    for name in _HOST_HEADERS:
        if name in headers:
            extracted[name] = headers[name]
    if "forwarded" in extracted:
        match = _FORWARDED_HOST_RE.search(extracted["forwarded"])
        if match:
            extracted["forwarded"] = match.group(1)
    return extracted


def _split_host_port(value: str) -> str:
    candidate = value.strip().strip("\"'").lower()
    if candidate.startswith("[") and "]" in candidate:
        return candidate[1:candidate.index("]")]
    if candidate.count(":") == 1 and candidate.rsplit(":", 1)[1].isdigit():
        return candidate.rsplit(":", 1)[0]
    return candidate


def _to_ip(value: str) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(_split_host_port(value))
    except ValueError:
        return None


def _is_private_or_metadata(host_value: str) -> bool:
    host = _split_host_port(host_value)
    if host in _METADATA_HOSTS or host == "localhost":
        return True
    ip = _to_ip(host)
    if ip is None:
        return False
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip in _METADATA_IPS)


def _is_external_domain(host_value: str) -> bool:
    host = _split_host_port(host_value)
    if not host or host == "localhost":
        return False
    if _to_ip(host) is not None:
        return False
    return "." in host and not host.endswith(".local")


def _multiple_values(value: str) -> bool:
    return "," in value


def _add_finding(
    findings: List[HostHeaderFinding],
    seen: set[str],
    check_id: str,
    header_name: str,
    evidence: str,
    detail: str,
    recommendation: str,
) -> None:
    dedup_key = f"{check_id}:{header_name}:{evidence}"
    if dedup_key in seen:
        return
    seen.add(dedup_key)
    findings.append(
        HostHeaderFinding(
            check_id=check_id,
            severity=_CHECK_SEVERITIES[check_id],
            title=_CHECK_TITLES[check_id],
            detail=detail,
            header_name=header_name,
            evidence=_truncate(evidence),
            recommendation=recommendation,
        )
    )


class HostHeaderAttackPack:
    """Evaluate inbound requests for host header poisoning patterns."""

    def __init__(self, block_on_severity: str = "HIGH") -> None:
        if block_on_severity not in _SEVERITY_ORDER:
            raise ValueError(f"Unsupported block_on_severity: {block_on_severity}")
        self.block_on_severity = block_on_severity

    def evaluate(self, request: HostHeaderRequest) -> HostHeaderEvalResult:
        headers = _extract_header_values(_normalise_headers(request.headers))
        canonical_host = _canonical_host(request.url)
        findings: List[HostHeaderFinding] = []
        seen: set[str] = set()

        if len(headers) >= 2:
            _add_finding(
                findings,
                seen,
                "HHO-001",
                "multiple",
                ", ".join(f"{name}={value}" for name, value in headers.items()),
                "Multiple host-routing headers were supplied, increasing override risk across proxies and origin routing layers.",
                "Allow only trusted forwarding headers at the edge and normalize upstream host-routing metadata before origin evaluation.",
            )

        for header_name, value in headers.items():
            stripped_value = value.strip()

            if _SCHEME_RE.match(stripped_value):
                _add_finding(
                    findings,
                    seen,
                    "HHO-002",
                    header_name,
                    stripped_value,
                    f"Header '{header_name}' contains an absolute URL or scheme rather than a canonical host value.",
                    "Reject host headers that include schemes and allow only bare host[:port] values.",
                )

            if _INVALID_HOST_RE.search(stripped_value):
                _add_finding(
                    findings,
                    seen,
                    "HHO-004",
                    header_name,
                    stripped_value,
                    f"Header '{header_name}' contains invalid characters, whitespace, encoding markers, or traversal-like content.",
                    "Enforce RFC-compliant host validation and block encoded, whitespace-padded, or path-bearing host values.",
                )

            if _multiple_values(stripped_value):
                _add_finding(
                    findings,
                    seen,
                    "HHO-006",
                    header_name,
                    stripped_value,
                    f"Header '{header_name}' carries multiple candidate host values in a single field.",
                    "Drop multi-valued host-routing headers unless a trusted proxy contract explicitly requires them.",
                )

            if _is_private_or_metadata(stripped_value):
                _add_finding(
                    findings,
                    seen,
                    "HHO-003",
                    header_name,
                    stripped_value,
                    f"Header '{header_name}' targets loopback, private addressing, or metadata infrastructure.",
                    "Block internal or metadata host targets at the WAF edge and restrict origin trust to approved public domains.",
                )

            if canonical_host and _is_external_domain(canonical_host):
                host_ip = _to_ip(stripped_value)
                if host_ip is not None:
                    _add_finding(
                        findings,
                        seen,
                        "HHO-007",
                        header_name,
                        stripped_value,
                        f"Header '{header_name}' uses an IP literal while the canonical request host '{canonical_host}' is a domain.",
                        "Prefer canonical domain validation and reject direct IP literal host overrides unless explicitly required.",
                    )

        host_value = headers.get("host")
        forwarded_candidates: Iterable[str] = (
            value for key, value in headers.items() if key != "host"
        )
        if host_value and _is_external_domain(host_value):
            for forwarded_value in forwarded_candidates:
                if _is_external_domain(forwarded_value):
                    if _split_host_port(host_value) != _split_host_port(forwarded_value):
                        _add_finding(
                            findings,
                            seen,
                            "HHO-005",
                            "host",
                            f"host={host_value}; forwarded={forwarded_value}",
                            "Host and forwarding headers disagree on the external target domain, which may enable cache poisoning or origin confusion.",
                            "Normalize and compare host-routing headers before forwarding traffic to the origin.",
                        )

        unique_ids = {finding.check_id for finding in findings}
        risk_score = min(100, sum(_CHECK_WEIGHTS[check_id] for check_id in unique_ids))
        threshold = _SEVERITY_ORDER[self.block_on_severity]
        blocked = any(_SEVERITY_ORDER[finding.severity] >= threshold for finding in findings)
        return HostHeaderEvalResult(findings=findings, risk_score=risk_score, blocked=blocked)

    def evaluate_many(self, requests: Iterable[HostHeaderRequest]) -> List[HostHeaderEvalResult]:
        return [self.evaluate(request) for request in requests]
