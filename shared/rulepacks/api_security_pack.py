"""
API Security Rulepack
========================
Defensive WAF rules targeting REST and GraphQL API attack surfaces —
authentication bypass, broken object-level authorization (BOLA/IDOR),
mass assignment, excessive data exposure, HTTP verb tampering, and
API-specific injection vectors.

Rule Categories
----------------
API-AUTH-001   Missing or malformed Authorization header on protected paths
API-AUTH-002   HTTP Basic Auth over non-HTTPS (credential exposure)
API-BOLA-001   Numeric object ID in URL path suggests IDOR scan pattern
API-BOLA-002   Automated IDOR probe — sequential ID enumeration
API-INJECT-001 GraphQL introspection enabled in production
API-INJECT-002 GraphQL batch query abuse (>N operations per request)
API-INJECT-003 Server-Side Template Injection tokens in API body/params
API-VERB-001   HTTP verb tampering (HEAD/OPTIONS/TRACE used to bypass auth)
API-EXPOSE-001 Sensitive field names in response (if checked client-side)
API-RATE-001   Burst of requests to credential endpoints (login, token, keys)

Usage::

    from shared.rulepacks.api_security_pack import (
        ApiSecurityRulepack,
        RuleMatch,
        Severity,
    )

    pack = ApiSecurityRulepack()
    matches = pack.evaluate(request)
    for m in matches:
        print(m.summary())
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class Action(str, Enum):
    BLOCK  = "BLOCK"
    LOG    = "LOG"
    ALLOW  = "ALLOW"


# ---------------------------------------------------------------------------
# Rule match
# ---------------------------------------------------------------------------

@dataclass
class RuleMatch:
    """
    A single rule match for an evaluated request.

    Attributes:
        rule_id:     Rule identifier (e.g. ``API-AUTH-001``).
        severity:    Match severity.
        action:      Recommended action.
        title:       Short description.
        detail:      Detailed explanation of the match.
        matched_on:  Field or header that triggered the rule.
        matched_value: Sanitized excerpt of the offending value.
    """
    rule_id:       str
    severity:      Severity
    action:        Action
    title:         str
    detail:        str
    matched_on:    str = ""
    matched_value: str = ""

    def summary(self) -> str:
        return (
            f"[{self.severity.value}] {self.rule_id} {self.action.value} | "
            f"{self.title} | matched_on={self.matched_on}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id":       self.rule_id,
            "severity":      self.severity.value,
            "action":        self.action.value,
            "title":         self.title,
            "detail":        self.detail,
            "matched_on":    self.matched_on,
            "matched_value": self.matched_value,
        }


# ---------------------------------------------------------------------------
# Compiled pattern sets
# ---------------------------------------------------------------------------

# Paths that require authentication
_PROTECTED_PATH_PREFIXES = (
    "/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/",
    "/admin/", "/internal/", "/management/",
)

# Paths that explicitly do NOT require auth (allow-list)
_AUTH_EXEMPT_PATHS = (
    "/api/health", "/api/ping", "/api/version",
    "/v1/auth/", "/v1/login", "/v1/register",
    "/v2/auth/", "/v2/login",
)

# Auth endpoints — rate limit targets
_AUTH_ENDPOINT_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"/auth/token",
        r"/oauth/token",
        r"/login",
        r"/signin",
        r"/api-key",
        r"/credentials",
        r"/session",
    ]
]

# HTTP Basic auth detection
_BASIC_AUTH_RE = re.compile(r"^Basic\s+", re.IGNORECASE)

# IDOR-susceptible path: /resource/{numeric-id}
_NUMERIC_ID_PATH_RE = re.compile(r"/\d{1,12}(?:/|$)")

# GraphQL introspection query
_GQL_INTROSPECTION_RE = re.compile(
    r"__schema|__type|__typename.*introspect",
    re.IGNORECASE,
)

# SSTI tokens common in template engines
_SSTI_PATTERNS = [
    re.compile(p) for p in [
        r"\{\{.*\}\}",           # Jinja2 / Twig / Handlebars
        r"\$\{.*\}",             # Freemarker / EL
        r"<#.*>",                # Freemarker directive
        r"\{%.*%\}",             # Liquid / Jinja blocks
        r"<%.*%>",               # ERB / ASP
        r"#\{.*\}",              # Ruby ERB expressions
    ]
]

# HTTP verbs often used to bypass authentication checks
_BYPASS_VERBS = {"HEAD", "OPTIONS", "TRACE", "CONNECT", "PATCH"}

# Sensitive field names commonly leaked in API responses
_SENSITIVE_FIELD_NAMES_RE = re.compile(
    r"\b(password|passwd|secret|api_?key|access_?token|private_?key|"
    r"credit_?card|ssn|social_?security|pin|cvv)\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# ApiSecurityRulepack
# ---------------------------------------------------------------------------

class ApiSecurityRulepack:
    """
    Evaluates an HTTP request dict against the API security rulepack.

    Request dict expected keys (all optional, defaults to empty/None):
      - method:   HTTP verb string (``GET``, ``POST``, etc.)
      - path:     URL path string (``/api/v1/users/42``)
      - headers:  Dict of header name → value
      - body:     Request body string or dict
      - params:   Query parameter dict
      - scheme:   ``http`` or ``https``
      - ip:       Client IP address string
      - session_request_count: int — number of requests in current session
                                (used for burst/IDOR heuristics)

    Args:
        graphql_batch_limit:     Maximum GraphQL operations per request (default 5).
        idor_burst_threshold:    Minimum sequential ID requests to flag BOLA-002 (default 10).
        rate_limit_burst:        Minimum requests to auth endpoint to flag API-RATE-001 (default 20).
        check_response_body:     If True, also evaluate ``response_body`` field for
                                 API-EXPOSE-001 (default False — server-side check only).
    """

    def __init__(
        self,
        graphql_batch_limit: int = 5,
        idor_burst_threshold: int = 10,
        rate_limit_burst: int = 20,
        check_response_body: bool = False,
    ) -> None:
        self._gql_batch_limit  = graphql_batch_limit
        self._idor_burst       = idor_burst_threshold
        self._rate_limit_burst = rate_limit_burst
        self._check_response   = check_response_body

    def evaluate(self, request: dict[str, Any]) -> list[RuleMatch]:
        """
        Evaluate a single request dict against all rules.

        Returns a list of RuleMatch objects (may be empty).
        """
        matches: list[RuleMatch] = []

        method  = _str(request, "method", "verb").upper() or "GET"
        path    = _str(request, "path", "url", "uri") or "/"
        headers = request.get("headers") or {}
        body    = request.get("body") or ""
        params  = request.get("params") or {}
        scheme  = _str(request, "scheme", "protocol").lower() or "https"
        session_count = int(request.get("session_request_count") or 0)

        body_str = body if isinstance(body, str) else _json_str(body)
        params_str = _json_str(params)
        combined_input = " ".join([body_str, params_str])

        matches.extend(self._check_auth(method, path, headers))
        matches.extend(self._check_basic_over_http(scheme, headers))
        matches.extend(self._check_idor(path, session_count))
        matches.extend(self._check_graphql(path, body_str))
        matches.extend(self._check_ssti(combined_input))
        matches.extend(self._check_verb_tampering(method, path))

        if self._check_response:
            response_body = _str(request, "response_body") or ""
            matches.extend(self._check_sensitive_exposure(response_body))

        matches.extend(self._check_auth_rate(path, session_count))

        return matches

    # ------------------------------------------------------------------
    # Rule implementations
    # ------------------------------------------------------------------

    def _check_auth(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
    ) -> list[RuleMatch]:
        """API-AUTH-001: Missing auth on protected paths."""
        if not _is_protected_path(path):
            return []
        if method in ("OPTIONS", "HEAD"):
            return []

        auth_header = _header(headers, "authorization")
        if auth_header:
            return []

        # Also accept cookie-based sessions
        cookie = _header(headers, "cookie")
        if cookie and ("session" in cookie.lower() or "token" in cookie.lower()):
            return []

        return [RuleMatch(
            rule_id="API-AUTH-001",
            severity=Severity.HIGH,
            action=Action.BLOCK,
            title="Missing Authorization header on protected API path",
            detail=(
                f"Request to '{path}' ({method}) carries no Authorization "
                "header and no session cookie. The endpoint appears to be "
                "protected but the request is unauthenticated."
            ),
            matched_on="headers.Authorization",
            matched_value="<absent>",
        )]

    def _check_basic_over_http(
        self,
        scheme: str,
        headers: dict[str, str],
    ) -> list[RuleMatch]:
        """API-AUTH-002: HTTP Basic Auth over non-HTTPS."""
        if scheme == "https":
            return []
        auth_header = _header(headers, "authorization")
        if not auth_header:
            return []
        if not _BASIC_AUTH_RE.match(auth_header):
            return []
        return [RuleMatch(
            rule_id="API-AUTH-002",
            severity=Severity.CRITICAL,
            action=Action.BLOCK,
            title="HTTP Basic Auth credentials transmitted over HTTP",
            detail=(
                "An Authorization: Basic header was detected on a non-HTTPS "
                "connection. Base64-encoded credentials are trivially decoded "
                "and exposed to network observers."
            ),
            matched_on="headers.Authorization + scheme",
            matched_value="Basic <redacted>",
        )]

    def _check_idor(self, path: str, session_count: int) -> list[RuleMatch]:
        """API-BOLA-001/002: Numeric ID in path and burst enumeration."""
        matches: list[RuleMatch] = []

        if _NUMERIC_ID_PATH_RE.search(path):
            matches.append(RuleMatch(
                rule_id="API-BOLA-001",
                severity=Severity.MEDIUM,
                action=Action.LOG,
                title="Numeric object ID in URL — potential IDOR target",
                detail=(
                    f"The path '{path}' contains a numeric ID segment. "
                    "Predictable identifiers are susceptible to IDOR attacks "
                    "when authorization is not enforced per-object."
                ),
                matched_on="path",
                matched_value=path,
            ))

        if session_count >= self._idor_burst and _NUMERIC_ID_PATH_RE.search(path):
            matches.append(RuleMatch(
                rule_id="API-BOLA-002",
                severity=Severity.HIGH,
                action=Action.BLOCK,
                title="Automated IDOR probe — sequential ID enumeration detected",
                detail=(
                    f"The session has issued {session_count} requests to "
                    "numeric-ID paths. This pattern is consistent with "
                    "automated BOLA/IDOR enumeration tooling."
                ),
                matched_on="path + session_request_count",
                matched_value=str(session_count),
            ))

        return matches

    def _check_graphql(self, path: str, body: str) -> list[RuleMatch]:
        """API-INJECT-001/002: GraphQL introspection and batch abuse."""
        matches: list[RuleMatch] = []

        is_graphql = "graphql" in path.lower() or '"query"' in body or "'query'" in body

        if is_graphql and _GQL_INTROSPECTION_RE.search(body):
            matches.append(RuleMatch(
                rule_id="API-INJECT-001",
                severity=Severity.MEDIUM,
                action=Action.BLOCK,
                title="GraphQL introspection query detected",
                detail=(
                    "The request body contains a GraphQL introspection query "
                    "(__schema / __type). Introspection should be disabled in "
                    "production to prevent schema enumeration by attackers."
                ),
                matched_on="body",
                matched_value="__schema/__type",
            ))

        if is_graphql:
            # Count top-level operations (heuristic: count `query` / `mutation` keywords)
            op_count = len(re.findall(r'\b(query|mutation|subscription)\b', body, re.IGNORECASE))
            if op_count > self._gql_batch_limit:
                matches.append(RuleMatch(
                    rule_id="API-INJECT-002",
                    severity=Severity.HIGH,
                    action=Action.BLOCK,
                    title="GraphQL batch query abuse",
                    detail=(
                        f"The request contains {op_count} GraphQL operations, "
                        f"exceeding the limit of {self._gql_batch_limit}. "
                        "Batched queries can be used to bypass rate limiting "
                        "and amplify resource consumption."
                    ),
                    matched_on="body",
                    matched_value=str(op_count),
                ))

        return matches

    def _check_ssti(self, input_str: str) -> list[RuleMatch]:
        """API-INJECT-003: SSTI tokens in request input."""
        for pattern in _SSTI_PATTERNS:
            m = pattern.search(input_str)
            if m:
                excerpt = m.group(0)[:80]
                return [RuleMatch(
                    rule_id="API-INJECT-003",
                    severity=Severity.CRITICAL,
                    action=Action.BLOCK,
                    title="Server-Side Template Injection token detected",
                    detail=(
                        "A template expression pattern was found in the request "
                        "body or query parameters. If the input is rendered by a "
                        "server-side template engine, this may result in arbitrary "
                        "code execution."
                    ),
                    matched_on="body/params",
                    matched_value=excerpt,
                )]
        return []

    def _check_verb_tampering(self, method: str, path: str) -> list[RuleMatch]:
        """API-VERB-001: Dangerous HTTP verb on API path."""
        if method not in _BYPASS_VERBS:
            return []
        if not _is_protected_path(path):
            return []
        if method == "OPTIONS":
            # CORS preflight is legitimate — log only
            return [RuleMatch(
                rule_id="API-VERB-001",
                severity=Severity.LOW,
                action=Action.LOG,
                title="OPTIONS request to protected API path",
                detail=(
                    f"An OPTIONS request was sent to '{path}'. While this may be "
                    "a CORS preflight, OPTIONS responses that expose sensitive "
                    "capabilities should be reviewed."
                ),
                matched_on="method",
                matched_value=method,
            )]
        return [RuleMatch(
            rule_id="API-VERB-001",
            severity=Severity.MEDIUM,
            action=Action.BLOCK,
            title=f"HTTP verb tampering — {method} on protected path",
            detail=(
                f"The HTTP method {method} was used on a protected API path "
                f"'{path}'. Unusual verbs are sometimes used to bypass "
                "authorization checks that only validate GET/POST."
            ),
            matched_on="method",
            matched_value=method,
        )]

    def _check_sensitive_exposure(self, response_body: str) -> list[RuleMatch]:
        """API-EXPOSE-001: Sensitive field names in response body."""
        m = _SENSITIVE_FIELD_NAMES_RE.search(response_body)
        if not m:
            return []
        return [RuleMatch(
            rule_id="API-EXPOSE-001",
            severity=Severity.HIGH,
            action=Action.LOG,
            title="Sensitive field name detected in API response",
            detail=(
                f"The response body contains the field name '{m.group(0)}'. "
                "Sensitive fields should be stripped from API responses to "
                "prevent excessive data exposure (OWASP API3)."
            ),
            matched_on="response_body",
            matched_value=m.group(0),
        )]

    def _check_auth_rate(self, path: str, session_count: int) -> list[RuleMatch]:
        """API-RATE-001: Burst to authentication endpoints."""
        if session_count < self._rate_limit_burst:
            return []
        for pattern in _AUTH_ENDPOINT_PATTERNS:
            if pattern.search(path):
                return [RuleMatch(
                    rule_id="API-RATE-001",
                    severity=Severity.HIGH,
                    action=Action.BLOCK,
                    title="Authentication endpoint rate limit exceeded",
                    detail=(
                        f"The session has sent {session_count} requests to the "
                        f"auth endpoint '{path}'. This pattern is consistent with "
                        "credential stuffing or brute-force attacks."
                    ),
                    matched_on="path + session_request_count",
                    matched_value=str(session_count),
                )]
        return []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_protected_path(path: str) -> bool:
    """Return True if path starts with a protected prefix and is not exempt."""
    for exempt in _AUTH_EXEMPT_PATHS:
        if path.startswith(exempt):
            return False
    for prefix in _PROTECTED_PATH_PREFIXES:
        if path.startswith(prefix):
            return True
    return False


def _str(d: dict[str, Any], *keys: str) -> str:
    for k in keys:
        v = d.get(k)
        if v is not None:
            return str(v)
    return ""


def _header(headers: dict[str, Any], name: str) -> str:
    """Case-insensitive header lookup."""
    name_lower = name.lower()
    for k, v in headers.items():
        if k.lower() == name_lower:
            return str(v)
    return ""


def _json_str(obj: Any) -> str:
    """Convert dict/list to a flat string for pattern matching."""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return " ".join(f"{k} {v}" for k, v in obj.items())
    if isinstance(obj, (list, tuple)):
        return " ".join(str(i) for i in obj)
    return str(obj) if obj else ""
