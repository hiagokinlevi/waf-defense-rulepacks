# graphql_security_pack.py
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
GraphQL Security Rulepack
==========================
Analyses and evaluates GraphQL requests for common abuse patterns including
query depth attacks, batch amplification, introspection leakage, field
duplication, alias abuse, directive injection, and SQL-style variable
injection embedded directly in the query string.

Rule IDs
---------
GQL-001   Query depth exceeds configured maximum
GQL-002   Batch query abuse (operations_count exceeds limit)
GQL-003   Introspection query detected (__schema / __type)
GQL-004   Query amplification via repeated field names
GQL-005   Alias abuse (excessive alias definitions)
GQL-006   Directive injection (non-standard @directive)
GQL-007   Variable injection / SQL patterns in query string

Usage::

    from shared.rulepacks.graphql_security_pack import (
        GraphQLSecurityPack,
        GraphQLRequest,
    )

    pack = GraphQLSecurityPack(max_depth=8)
    req  = GraphQLRequest(query="{ user { id name } }")
    result = pack.evaluate(req)
    print(result.summary())
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Severity levels
# ---------------------------------------------------------------------------

class SeverityLevel(int, Enum):
    """Ordinal severity for threshold comparisons."""
    INFO     = 0
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4


# ---------------------------------------------------------------------------
# Check weight registry
# ---------------------------------------------------------------------------

# Maps each check ID to its contribution toward the 0–100 risk score.
# The final score is the minimum of 100 and the sum of all *unique* fired IDs.
_CHECK_WEIGHTS: Dict[str, int] = {
    "GQL-001": 25,  # Deep query nesting
    "GQL-002": 25,  # Batch abuse
    "GQL-003": 15,  # Introspection
    "GQL-004": 20,  # Field duplication / amplification
    "GQL-005": 15,  # Alias abuse
    "GQL-006": 20,  # Directive injection
    "GQL-007": 15,  # Variable / SQL injection
}


# ---------------------------------------------------------------------------
# Allowed directives (standard + federation)
# ---------------------------------------------------------------------------

_ALLOWED_DIRECTIVES = frozenset({
    "include",
    "skip",
    "deprecated",
    "specifiedBy",
    "external",
    "requires",
    "provides",
    "key",
    "shareable",
    "inaccessible",
    "override",
    "link",
})


# ---------------------------------------------------------------------------
# Pre-compiled patterns
# ---------------------------------------------------------------------------

# Regex to extract all alias definitions inside a GraphQL query body.
# Aliases take the form `aliasName: fieldName`; we capture the left-hand side.
_ALIAS_RE = re.compile(r"(\w+)\s*:")

# Regex to extract candidate field names: words that appear right before
# an opening brace, opening paren (argument list), or whitespace boundary.
_FIELD_NAME_RE = re.compile(r"\b(\w+)\s*(?:\(|\{|\n|\s)")

# All @directive references in a query.
_DIRECTIVE_RE = re.compile(r"@(\w+)")

# SQL injection patterns that should not appear hard-coded in query strings.
_SQL_INJECTION_RE = re.compile(
    r"(?:SELECT|UNION|DROP|INSERT|UPDATE|DELETE|WHERE)\b|['\";]--|\/\*",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class GraphQLRequest:
    """
    Represents a single inbound GraphQL request to be evaluated.

    Attributes:
        query:           Raw GraphQL query / mutation / subscription string.
        operation_name:  Optional named operation within the document.
        variables:       Optional variables dictionary supplied with the request.
        operations_count: For batched requests, the total number of operation
                         objects in the payload (default 1).
        source_ip:       Originating client IP address for logging purposes.
    """
    query: str
    operation_name: Optional[str] = None
    variables: Optional[dict] = None
    operations_count: int = 1
    source_ip: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dictionary suitable for JSON output."""
        return {
            "query":            self.query,
            "operation_name":   self.operation_name,
            "variables":        self.variables,
            "operations_count": self.operations_count,
            "source_ip":        self.source_ip,
        }


@dataclass
class GraphQLFinding:
    """
    Represents a single security finding raised against a GraphQL request.

    Attributes:
        check_id:        Rule identifier (e.g. ``GQL-001``).
        severity:        Severity label: CRITICAL, HIGH, MEDIUM, LOW, or INFO.
        rule_name:       Short human-readable rule name.
        detail:          Detailed explanation of why the rule fired.
        recommendation:  Remediation guidance.
    """
    check_id:       str
    severity:       str
    rule_name:      str
    detail:         str
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dictionary suitable for JSON output."""
        return {
            "check_id":       self.check_id,
            "severity":       self.severity,
            "rule_name":      self.rule_name,
            "detail":         self.detail,
            "recommendation": self.recommendation,
        }


@dataclass
class GraphQLEvalResult:
    """
    Aggregated evaluation result for a single GraphQL request.

    Attributes:
        findings:          Ordered list of GraphQLFinding objects (may be empty).
        risk_score:        Integer 0–100 representing cumulative risk.
        blocked:           True if at least one finding meets or exceeds the
                           configured block_on_severity threshold.
        block_on_severity: The severity threshold used when computing blocked.
    """
    findings:          List[GraphQLFinding]
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
        return (
            f"GraphQL eval [{status}] | risk_score={self.risk_score} | "
            f"{n} {finding_word}: "
            + ", ".join(f.check_id for f in self.findings)
            if self.findings
            else f"GraphQL eval [{status}] | risk_score={self.risk_score} | 0 findings"
        )

    def by_severity(self) -> Dict[str, List[GraphQLFinding]]:
        """
        Group findings by severity label.

        Returns a dict with keys for every known severity level; each value
        is a (possibly empty) list of GraphQLFinding objects.
        """
        result: Dict[str, List[GraphQLFinding]] = {
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
                # Unknown severity — add bucket dynamically rather than discard
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
# GraphQLSecurityPack
# ---------------------------------------------------------------------------

class GraphQLSecurityPack:
    """
    WAF security rulepack for GraphQL-specific abuse detection.

    The pack runs seven deterministic checks against each GraphQLRequest
    and aggregates the results into a GraphQLEvalResult.

    Args:
        max_depth:           Maximum allowed nesting depth (default 10).
        max_operations:      Maximum batch operations per request (default 5).
        max_aliases:         Maximum alias definitions per request (default 10).
        max_field_duplicates: Maximum times a single field name may repeat
                             before triggering GQL-004 (default 15).
        block_on_severity:   Minimum finding severity that causes blocked=True
                             (default ``"HIGH"``).

    Example::

        pack = GraphQLSecurityPack(max_depth=8, block_on_severity="MEDIUM")
        result = pack.evaluate(GraphQLRequest(query="..."))
        if result.blocked:
            raise PermissionError(result.summary())
    """

    def __init__(
        self,
        max_depth:            int = 10,
        max_operations:       int = 5,
        max_aliases:          int = 10,
        max_field_duplicates: int = 15,
        block_on_severity:    str = "HIGH",
    ) -> None:
        self._max_depth            = max_depth
        self._max_operations       = max_operations
        self._max_aliases          = max_aliases
        self._max_field_duplicates = max_field_duplicates
        self._block_on_severity    = block_on_severity

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def evaluate(self, request: GraphQLRequest) -> GraphQLEvalResult:
        """
        Evaluate a single GraphQLRequest against all seven security checks.

        Returns a GraphQLEvalResult with findings, risk_score, and blocked flag.
        """
        findings: List[GraphQLFinding] = []

        # Run all checks; each returns either a finding or None
        for check_fn in (
            self._check_gql_001_depth,
            self._check_gql_002_batch,
            self._check_gql_003_introspection,
            self._check_gql_004_field_duplication,
            self._check_gql_005_alias_abuse,
            self._check_gql_006_directive_injection,
            self._check_gql_007_variable_injection,
        ):
            result = check_fn(request)
            if result is not None:
                findings.append(result)

        # Compute risk score: sum of unique fired check weights, capped at 100
        fired_ids = {f.check_id for f in findings}
        risk_score = min(100, sum(_CHECK_WEIGHTS.get(cid, 0) for cid in fired_ids))

        # Determine blocked status based on configured severity threshold
        blocked = any(
            self._severity_value(f.severity) >= self._severity_value(self._block_on_severity)
            for f in findings
        )

        return GraphQLEvalResult(
            findings=findings,
            risk_score=risk_score,
            blocked=blocked,
            block_on_severity=self._block_on_severity,
        )

    def evaluate_many(
        self,
        requests: List[GraphQLRequest],
    ) -> List[GraphQLEvalResult]:
        """
        Evaluate a batch of GraphQL requests.

        Returns a list of GraphQLEvalResult in the same order as the input.
        """
        return [self.evaluate(req) for req in requests]

    # ------------------------------------------------------------------
    # Individual check implementations
    # ------------------------------------------------------------------

    def _check_gql_001_depth(
        self,
        request: GraphQLRequest,
    ) -> Optional[GraphQLFinding]:
        """
        GQL-001: Query depth exceeds max_depth.

        Counts the maximum nesting depth of ``{`` characters in the query,
        skipping brace-like characters inside string literals (``"..."``)
        so that string values do not inflate the depth count.
        """
        query = request.query
        current_depth = 0
        max_depth_seen = 0
        in_string = False
        i = 0

        while i < len(query):
            ch = query[i]

            if in_string:
                # Honour escape sequences inside string literals
                if ch == "\\" and i + 1 < len(query):
                    i += 2  # skip escaped character
                    continue
                if ch == '"':
                    in_string = False
            else:
                if ch == '"':
                    in_string = True
                elif ch == "{":
                    current_depth += 1
                    if current_depth > max_depth_seen:
                        max_depth_seen = current_depth
                elif ch == "}":
                    current_depth -= 1

            i += 1

        if max_depth_seen > self._max_depth:
            return GraphQLFinding(
                check_id="GQL-001",
                severity="HIGH",
                rule_name="Excessive Query Depth",
                detail=(
                    f"Query nesting depth {max_depth_seen} exceeds the "
                    f"configured maximum of {self._max_depth}. Deep queries "
                    "can cause exponential resolver execution and denial-of-service."
                ),
                recommendation=(
                    "Enforce a maximum query depth in the GraphQL server layer "
                    "(e.g. graphql-depth-limit). Reject or truncate queries that "
                    f"exceed depth {self._max_depth}."
                ),
            )
        return None

    def _check_gql_002_batch(
        self,
        request: GraphQLRequest,
    ) -> Optional[GraphQLFinding]:
        """
        GQL-002: Batch query abuse.

        Fires when operations_count exceeds max_operations.  Batched GraphQL
        requests bypass per-request rate limiting and can amplify server load.
        """
        if request.operations_count > self._max_operations:
            return GraphQLFinding(
                check_id="GQL-002",
                severity="HIGH",
                rule_name="Batch Query Abuse",
                detail=(
                    f"Request contains {request.operations_count} batched operations, "
                    f"exceeding the configured limit of {self._max_operations}. "
                    "Batch abuse can be used to bypass rate limits and amplify "
                    "server resource consumption."
                ),
                recommendation=(
                    "Limit batch request sizes at the GraphQL gateway or load balancer. "
                    f"Reject requests containing more than {self._max_operations} operations."
                ),
            )
        return None

    def _check_gql_003_introspection(
        self,
        request: GraphQLRequest,
    ) -> Optional[GraphQLFinding]:
        """
        GQL-003: Introspection query detected.

        Fires when the query string contains ``__schema`` or ``__type`` as a
        substring.  Introspection exposes the full API schema to potential
        attackers in production environments.
        """
        query = request.query
        if "__schema" in query or "__type" in query:
            trigger = "__schema" if "__schema" in query else "__type"
            return GraphQLFinding(
                check_id="GQL-003",
                severity="MEDIUM",
                rule_name="GraphQL Introspection Query",
                detail=(
                    f"The query contains the introspection field '{trigger}'. "
                    "Introspection allows clients to enumerate the full API schema, "
                    "types, and fields, which aids reconnaissance by attackers."
                ),
                recommendation=(
                    "Disable introspection in production GraphQL deployments. "
                    "Allow introspection only in development environments behind "
                    "authentication. Consider using schema-based allow-listing instead."
                ),
            )
        return None

    def _check_gql_004_field_duplication(
        self,
        request: GraphQLRequest,
    ) -> Optional[GraphQLFinding]:
        """
        GQL-004: Query amplification via field duplication.

        Counts candidate field names with the regex ``\\b(\\w+)\\s*(?:\\(|{|\\n|\\s)``
        and fires when any single name appears more than max_field_duplicates times.
        Repeated field names cause the resolver to be called multiple times per
        request, multiplying backend load.
        """
        query = request.query
        tokens = _FIELD_NAME_RE.findall(query)

        # Count occurrences of each candidate token
        counts: Dict[str, int] = {}
        for token in tokens:
            counts[token] = counts.get(token, 0) + 1

        # Find the worst offender
        worst_field: Optional[str] = None
        worst_count = 0
        for token, count in counts.items():
            if count > worst_count:
                worst_count = count
                worst_field = token

        if worst_count > self._max_field_duplicates:
            return GraphQLFinding(
                check_id="GQL-004",
                severity="HIGH",
                rule_name="Field Duplication Amplification",
                detail=(
                    f"Field '{worst_field}' appears {worst_count} times in the query, "
                    f"exceeding the configured limit of {self._max_field_duplicates}. "
                    "Duplicated fields cause the same resolver to execute multiple times, "
                    "amplifying backend database and service calls."
                ),
                recommendation=(
                    "Deduplicate fields during query normalization at the gateway. "
                    "Enforce per-query field occurrence limits in the GraphQL execution layer."
                ),
            )
        return None

    def _check_gql_005_alias_abuse(
        self,
        request: GraphQLRequest,
    ) -> Optional[GraphQLFinding]:
        """
        GQL-005: Alias abuse.

        Counts alias definitions using the pattern ``\\w+\\s*:`` and fires when
        the total exceeds max_aliases.  Aliases allow the same field to be
        requested many times under different names, bypassing field-level
        deduplication and amplifying resolver execution.
        """
        query = request.query
        aliases = _ALIAS_RE.findall(query)
        alias_count = len(aliases)

        if alias_count > self._max_aliases:
            return GraphQLFinding(
                check_id="GQL-005",
                severity="MEDIUM",
                rule_name="Alias Abuse",
                detail=(
                    f"Query contains {alias_count} alias definitions, exceeding "
                    f"the configured maximum of {self._max_aliases}. Excessive "
                    "aliases are used to invoke the same resolver repeatedly under "
                    "different names, circumventing field deduplication protections."
                ),
                recommendation=(
                    "Limit the number of aliases per query at the GraphQL gateway. "
                    "Consider using query cost analysis to assign a cost to each "
                    "alias and reject high-cost queries."
                ),
            )
        return None

    def _check_gql_006_directive_injection(
        self,
        request: GraphQLRequest,
    ) -> Optional[GraphQLFinding]:
        """
        GQL-006: Directive injection.

        Extracts all ``@name`` directives from the query and fires when any
        name is not in the standard/federation allow-list.  Unknown directives
        may indicate attempts to manipulate server-side execution or exploit
        directive-processing bugs.
        """
        query = request.query
        found_directives = _DIRECTIVE_RE.findall(query)

        for directive_name in found_directives:
            if directive_name not in _ALLOWED_DIRECTIVES:
                return GraphQLFinding(
                    check_id="GQL-006",
                    severity="HIGH",
                    rule_name="Directive Injection",
                    detail=(
                        f"Query uses the non-standard directive '@{directive_name}'. "
                        "Unknown directives may attempt to exploit directive-processing "
                        "vulnerabilities or override server-side execution behaviour."
                    ),
                    recommendation=(
                        "Validate all directives against a strict allow-list before "
                        "execution. Reject queries containing directives not registered "
                        "in the server's schema."
                    ),
                )
        return None

    def _check_gql_007_variable_injection(
        self,
        request: GraphQLRequest,
    ) -> Optional[GraphQLFinding]:
        """
        GQL-007: Variable injection / SQL patterns embedded in query string.

        Fires when the query string contains SQL keywords or injection
        characters that indicate an attempt to embed raw SQL inside a GraphQL
        string literal (e.g. inside a ``filter`` argument value).  Legitimate
        dynamic values should always be supplied via the ``variables`` dict.
        """
        query = request.query
        match = _SQL_INJECTION_RE.search(query)

        if match:
            excerpt = match.group(0)[:60]
            return GraphQLFinding(
                check_id="GQL-007",
                severity="MEDIUM",
                rule_name="Variable Injection / SQL Pattern",
                detail=(
                    f"Query string contains a potential SQL injection pattern: "
                    f"'{excerpt}'. Hard-coded SQL keywords or injection characters "
                    "in a GraphQL query may indicate an attempt to exploit an "
                    "unsafe resolver that passes query values directly to a database."
                ),
                recommendation=(
                    "Always supply dynamic values through the GraphQL variables "
                    "mechanism rather than interpolating them into the query string. "
                    "Ensure resolvers use parameterised queries when accessing databases."
                ),
            )
        return None

    # ------------------------------------------------------------------
    # Severity ordering helper
    # ------------------------------------------------------------------

    @staticmethod
    def _severity_value(severity: str) -> int:
        """
        Map a severity label to its integer ordinal.

        Used for threshold comparisons (e.g. blocked determination).
        """
        return {
            "CRITICAL": 4,
            "HIGH":     3,
            "MEDIUM":   2,
            "LOW":      1,
            "INFO":     0,
        }.get(severity.upper(), 0)
