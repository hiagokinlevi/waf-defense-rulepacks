"""
Rate Limit Policy Generator
==============================
Generates rate limiting configurations for multiple WAF/proxy vendors.
Supports IP-based, path-based, and header-based rate limiting with
configurable windows, thresholds, and actions.

Supported Vendors
-----------------
cloudflare    Cloudflare Rate Limiting rules (JSON)
aws_waf       AWS WAF rate-based rules (JSON)
nginx         Nginx limit_req_zone configuration (text)

Usage::

    from shared.rulepacks.rate_limit_policy import RateLimitPolicyGenerator, RateLimitRule

    rule = RateLimitRule(
        rule_id="RL-LOGIN-001",
        name="Login endpoint rate limit",
        path_pattern="/api/v1/auth/login",
        threshold=10,
        window_seconds=60,
        action="block",
        match_key="ip",
    )
    gen = RateLimitPolicyGenerator()
    cf_config = gen.to_cloudflare([rule])
    aws_config = gen.to_aws_waf([rule])
    nginx_config = gen.to_nginx([rule])
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class MatchKey(str, Enum):
    """Key used to aggregate / identify the request source for rate limiting."""

    IP = "ip"          # Source IP address (most common)
    HEADER = "header"  # Arbitrary request header (e.g. X-API-Key, X-Forwarded-For)
    COOKIE = "cookie"  # Cookie value (session-based limiting)
    QUERY = "query"    # Query-string parameter value


class RuleAction(str, Enum):
    """Action taken when the rate limit threshold is exceeded."""

    BLOCK = "block"          # Hard block — return 429/403
    CHALLENGE = "challenge"  # Present a CAPTCHA / JS challenge (Cloudflare)
    LOG = "log"              # Log only — no enforcement; useful for baselining
    THROTTLE = "throttle"    # Slow down / queue the request rather than hard-block


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class RateLimitRule:
    """Single rate-limit rule describing one protected endpoint or path prefix."""

    # Unique identifier used as the rule handle across all vendor exports
    rule_id: str

    # Human-readable label surfaced in dashboards and config comments
    name: str

    # URL path or prefix to match (e.g. "/api/v1/auth/login")
    path_pattern: str

    # Maximum number of matching requests allowed within *window_seconds*
    threshold: int

    # Rolling time window in seconds over which *threshold* is measured
    window_seconds: int

    # Enforcement action when the threshold is exceeded
    action: RuleAction = RuleAction.BLOCK

    # Aggregation key — what identifies a "unique client"
    match_key: MatchKey = MatchKey.IP

    # Only relevant when match_key == MatchKey.HEADER; names the header to read
    header_name: str = ""

    # Soft switch: disabled rules are exported but marked inactive where supported
    enabled: bool = True

    # Arbitrary labels for grouping, filtering, or CI pipeline tagging
    tags: List[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self) -> None:
        """Raise *ValueError* when the rule contains logically invalid values.

        Checks performed
        ----------------
        - threshold must be a positive integer
        - window_seconds must be a positive integer
        - path_pattern must be a non-empty string
        """
        if self.threshold <= 0:
            raise ValueError(
                f"Rule '{self.rule_id}': threshold must be > 0, got {self.threshold}"
            )
        if self.window_seconds <= 0:
            raise ValueError(
                f"Rule '{self.rule_id}': window_seconds must be > 0, "
                f"got {self.window_seconds}"
            )
        if not self.path_pattern or not self.path_pattern.strip():
            raise ValueError(
                f"Rule '{self.rule_id}': path_pattern must not be empty"
            )

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict:
        """Return a plain-dict representation suitable for JSON serialization.

        Enum fields are serialized to their `.value` strings so the output
        is vendor/framework-agnostic and safe to store in JSON/YAML configs.
        """
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "path_pattern": self.path_pattern,
            "threshold": self.threshold,
            "window_seconds": self.window_seconds,
            "action": self.action.value,       # e.g. "block"
            "match_key": self.match_key.value, # e.g. "ip"
            "header_name": self.header_name,
            "enabled": self.enabled,
            "tags": list(self.tags),
        }


@dataclass
class RateLimitPolicy:
    """Container that groups multiple :class:`RateLimitRule` objects into a named policy."""

    # Ordered list of rules; earlier rules are evaluated first in most vendors
    rules: List[RateLimitRule]

    # Logical name for this policy (e.g. "api-gateway-prod")
    policy_name: str = "default"

    # Optional prose description rendered in generated config file headers
    description: str = ""

    # Unix epoch timestamp set at instantiation for audit/provenance tracking
    generated_at: float = field(default_factory=time.time)

    # ------------------------------------------------------------------
    # Convenience accessors
    # ------------------------------------------------------------------

    @property
    def enabled_rules(self) -> List[RateLimitRule]:
        """Return only the rules whose *enabled* flag is *True*."""
        return [r for r in self.rules if r.enabled]

    def rules_for_path(self, path: str) -> List[RateLimitRule]:
        """Return rules whose *path_pattern* matches *path*.

        A match occurs when the stored pattern is contained in (is a prefix /
        substring of) *path* **or** when *path* exactly equals *path_pattern*.
        This intentionally mirrors how most reverse-proxies do prefix routing.
        """
        matched: List[RateLimitRule] = []
        for rule in self.rules:
            # Exact match or prefix/substring containment
            if rule.path_pattern == path or rule.path_pattern in path:
                matched.append(rule)
        return matched

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict:
        """Return a fully serializable dict representation of the policy."""
        return {
            "policy_name": self.policy_name,
            "description": self.description,
            "generated_at": self.generated_at,
            "rules": [r.to_dict() for r in self.rules],
        }


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

class RateLimitPolicyGenerator:
    """Converts :class:`RateLimitRule` objects to vendor-specific configurations.

    All ``to_*`` methods accept a list of rules and return either a list of
    dicts (Cloudflare, AWS WAF) or a formatted string (Nginx).  Rules are
    processed in the order they are provided; callers are responsible for
    sorting by priority before passing them in.
    """

    # ------------------------------------------------------------------
    # Cloudflare
    # ------------------------------------------------------------------

    def to_cloudflare(self, rules: List[RateLimitRule]) -> List[Dict]:
        """Generate Cloudflare Rate Limiting rule objects.

        Output format mirrors the Cloudflare v4 API schema for rate-limiting
        rules attached to a zone ruleset.  Each dict can be submitted directly
        to ``PUT /zones/{zone_id}/rulesets/phases/http_ratelimit/entrypoint``.

        Parameters
        ----------
        rules:
            Ordered list of :class:`RateLimitRule` instances to convert.

        Returns
        -------
        List[Dict]
            One dict per rule in the same order as *rules*.
        """
        output: List[Dict] = []

        for rule in rules:
            # Build the Cloudflare-native rule representation
            cf_rule: Dict = {
                "id": rule.rule_id,
                "description": rule.name,
                # URL match expression — uses Cloudflare's "contains" operator
                "match": {
                    "request": {
                        "url": {
                            "path": {
                                "value": rule.path_pattern,
                                "operator": "contains",
                            }
                        }
                    }
                },
                # Cloudflare uses "threshold" (requests) + "period" (seconds)
                "threshold": rule.threshold,
                "period": rule.window_seconds,
                # Action string: "block", "challenge", "log", "throttle"
                "action": rule.action.value,
                "enabled": rule.enabled,
            }
            output.append(cf_rule)

        return output

    # ------------------------------------------------------------------
    # AWS WAF
    # ------------------------------------------------------------------

    def to_aws_waf(self, rules: List[RateLimitRule]) -> List[Dict]:
        """Generate AWS WAF v2 rate-based rule objects.

        Output format is compatible with ``aws wafv2 create-web-acl`` and
        ``aws wafv2 update-web-acl`` request bodies.  Rules use a
        ``RateBasedStatement`` with an optional ``ScopeDownStatement`` that
        restricts rate counting to the specified path.

        Aggregation key mapping
        -----------------------
        MatchKey.IP       → ``"IP"``   (native source IP)
        anything else     → ``"FORWARDED_IP"``  (X-Forwarded-For / custom header)

        Action mapping
        --------------
        RuleAction.BLOCK  → ``{"Block": {}}``
        all others        → ``{"Count": {}}``  (count = log in AWS WAF terms)

        Parameters
        ----------
        rules:
            Ordered list of :class:`RateLimitRule` instances to convert.

        Returns
        -------
        List[Dict]
            One dict per rule; Priority is 1-indexed and reflects list order.
        """
        output: List[Dict] = []

        for idx, rule in enumerate(rules):
            # AWS WAF aggregates by IP or by X-Forwarded-For (FORWARDED_IP)
            aggregate_key_type = (
                "IP" if rule.match_key == MatchKey.IP else "FORWARDED_IP"
            )

            # Only hard BLOCK maps to the Block action; everything else counts
            if rule.action == RuleAction.BLOCK:
                waf_action: Dict = {"Block": {}}
            else:
                waf_action = {"Count": {}}

            aws_rule: Dict = {
                "Name": rule.rule_id,
                # Priority is 1-indexed; lower numbers are evaluated first
                "Priority": idx + 1,
                "Statement": {
                    "RateBasedStatement": {
                        # AWS WAF rate limit window is always 5 minutes (300 s);
                        # threshold is the count per that window.
                        "Limit": rule.threshold,
                        "AggregateKeyType": aggregate_key_type,
                        # Scope down: only count requests that match the path
                        "ScopeDownStatement": {
                            "ByteMatchStatement": {
                                "SearchString": rule.path_pattern,
                                "FieldToMatch": {"UriPath": {}},
                                "TextTransformations": [
                                    {"Priority": 0, "Type": "LOWERCASE"}
                                ],
                                "PositionalConstraint": "CONTAINS",
                            }
                        },
                    }
                },
                "Action": waf_action,
                # Visibility config enables CloudWatch metrics and sampled requests
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": rule.rule_id,
                },
            }
            output.append(aws_rule)

        return output

    # ------------------------------------------------------------------
    # Nginx
    # ------------------------------------------------------------------

    def to_nginx(self, rules: List[RateLimitRule]) -> str:
        """Generate an Nginx ``limit_req_zone`` + ``location`` block configuration.

        Each rule produces:
        1. A ``limit_req_zone`` directive in the ``http`` context that defines
           the shared memory zone name, size, and request rate.
        2. A ``location`` block that references the zone and sets burst/nodelay.

        Rate calculation
        ----------------
        Nginx rate units are **r/s** (requests per second) or **r/m** (per
        minute).  This method chooses the unit as follows:

        - ``window_seconds <= 60``  →  use ``r/m`` (per minute).
          The rate is simply the *threshold* value (requests per window).
        - ``window_seconds > 60``   →  convert to ``r/s``.
          Rate = max(1, threshold // window_seconds).

        Burst
        -----
        ``burst = max(1, threshold // 5)``

        Parameters
        ----------
        rules:
            Ordered list of :class:`RateLimitRule` instances to convert.

        Returns
        -------
        str
            A multi-line string ready to be included in an ``nginx.conf`` or a
            ``conf.d/`` snippet.  Zone directives go in the ``http`` block;
            location blocks go inside a ``server`` block.
        """
        zone_lines: List[str] = ["# Rate limit zones"]
        location_lines: List[str] = ["# Location blocks"]

        for rule in rules:
            zone_name = f"{rule.rule_id}_zone"
            burst = max(1, rule.threshold // 5)

            # Determine the rate string (r/m vs r/s)
            if rule.window_seconds <= 60:
                # Express as requests-per-minute; threshold == count per window
                rate_str = f"{rule.threshold}r/m"
            else:
                # Convert to requests-per-second, flooring to minimum of 1
                rps = max(1, rule.threshold // rule.window_seconds)
                rate_str = f"{rps}r/s"

            # limit_req_zone directive — goes in the http { } context
            zone_lines.append(
                f"limit_req_zone $binary_remote_addr "
                f"zone={zone_name}:10m "
                f"rate={rate_str};"
            )

            # location block — goes inside a server { } context
            location_lines.append(
                f"location {rule.path_pattern} {{"
            )
            location_lines.append(
                f"    limit_req zone={zone_name} burst={burst} nodelay;"
            )
            location_lines.append("    limit_req_status 429;")
            location_lines.append("}")

        # Combine zones and location blocks with a blank separator line
        return "\n".join(zone_lines) + "\n\n" + "\n".join(location_lines)

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------

    def validate_all(self, rules: List[RateLimitRule]) -> List[str]:
        """Validate every rule and collect error messages.

        Unlike :meth:`RateLimitRule.validate` which raises immediately, this
        method tolerates all errors and returns them as a list so callers can
        surface the full set of problems in one pass (e.g. in CI pre-flight).

        Parameters
        ----------
        rules:
            Rules to validate.

        Returns
        -------
        List[str]
            Empty list means every rule is valid.  Each string in a non-empty
            list is the ``str()`` of a :class:`ValueError` raised by
            :meth:`RateLimitRule.validate`.
        """
        errors: List[str] = []
        for rule in rules:
            try:
                rule.validate()
            except ValueError as exc:
                errors.append(str(exc))
        return errors

    # ------------------------------------------------------------------
    # Deserialization
    # ------------------------------------------------------------------

    def from_dict_list(self, data: List[Dict]) -> List[RateLimitRule]:
        """Deserialize a list of dicts produced by :meth:`RateLimitRule.to_dict`.

        This is the inverse of ``[r.to_dict() for r in rules]``.  String enum
        values are converted back to their typed counterparts.

        Parameters
        ----------
        data:
            List of plain dicts, typically loaded from JSON or YAML.

        Returns
        -------
        List[RateLimitRule]
            Reconstructed rule objects in the same order as *data*.
        """
        rules: List[RateLimitRule] = []

        for item in data:
            rule = RateLimitRule(
                rule_id=item["rule_id"],
                name=item["name"],
                path_pattern=item["path_pattern"],
                threshold=item["threshold"],
                window_seconds=item["window_seconds"],
                # Coerce string back to enum; raises KeyError for unknown values
                action=RuleAction(item["action"]),
                match_key=MatchKey(item["match_key"]),
                header_name=item.get("header_name", ""),
                enabled=item.get("enabled", True),
                tags=list(item.get("tags", [])),
            )
            rules.append(rule)

        return rules
