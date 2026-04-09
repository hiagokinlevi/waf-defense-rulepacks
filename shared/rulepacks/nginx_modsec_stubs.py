"""
Nginx and ModSecurity Rate-Limit Output Stubs
===============================================
Generates Nginx and ModSecurity configuration snippets from RateLimitRule
specifications.  These are starting-point configs — they map the declarative
RateLimitRule spec to the closest native construct in each platform.

Nginx: limit_req_zone / limit_req directives (ngx_http_limit_req_module).
ModSecurity: SecAction counter + SecRule threshold guard using the
ip.* variable namespace (requires mod_security2 initcol support).

Usage:
    from shared.rulepacks.nginx_modsec_stubs import (
        generate_nginx_rate_limit,
        generate_modsec_rule,
        export_pack_nginx,
        export_pack_modsec,
    )
    from shared.rulepacks.rate_limit_rulepack import build_login_bruteforce_pack

    pack = build_login_bruteforce_pack()
    nginx_conf = export_pack_nginx(pack)
    modsec_conf = export_pack_modsec(pack)
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shared.rulepacks.rate_limit_rulepack import RateLimitRule, RateLimitRulepack

from shared.rulepacks.rate_limit_rulepack import RateLimitAction


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _zone_name(rule: "RateLimitRule") -> str:
    """Convert rule name to a valid Nginx zone / ModSecurity variable name."""
    return re.sub(r"[^a-z0-9_]", "_", rule.name.lower().strip()).strip("_") or "rate_zone"


def _nginx_rate(rule: "RateLimitRule") -> str:
    """
    Compute an Nginx rate string (e.g. "10r/s" or "5r/m") from requests/window.

    Nginx supports r/s and r/m natively.  We express sub-60-second windows
    as r/m where possible to keep the config readable.
    """
    if rule.window_seconds <= 0:
        return "1r/s"
    rps = rule.requests / rule.window_seconds
    if rps >= 1:
        # Whole requests-per-second
        return f"{max(1, int(rps))}r/s"
    else:
        # Express as per-minute (Nginx doesn't support fractional r/s)
        rpm = max(1, int(rule.requests * 60 / rule.window_seconds))
        return f"{rpm}r/m"


# ---------------------------------------------------------------------------
# Nginx
# ---------------------------------------------------------------------------

def generate_nginx_rate_limit(rule: "RateLimitRule", zone_size_mb: int = 10) -> str:
    """
    Generate an Nginx rate-limit config snippet for a single RateLimitRule.

    Returns a self-contained comment block plus two config directives:
      - limit_req_zone — place in the http {} context
      - limit_req     — place in the matching location {} block

    Args:
        rule:          The RateLimitRule to convert.
        zone_size_mb:  Shared memory zone size in MB (default 10).

    Returns:
        Multi-line string containing both directives with inline comments.
    """
    zone = _zone_name(rule)
    rate = _nginx_rate(rule)
    burst = max(1, rule.requests // 2)

    if rule.action == RateLimitAction.BLOCK:
        action_comment = "# Excess requests are rejected with 429 Too Many Requests"
        status_line = "limit_req_status 429;"
    elif rule.action == RateLimitAction.LOG:
        action_comment = "# Excess requests are passed through (logging only)"
        status_line = "# limit_req_status 429;  # disabled: log-only mode"
    else:
        action_comment = "# Excess requests receive a JS/CAPTCHA challenge (not native in Nginx)"
        status_line = "limit_req_status 429;  # adjust for challenge integration"

    return (
        f"# --------------------------------------------------------\n"
        f"# waf-defense-rulepacks — Nginx rate-limit stub\n"
        f"# Rule: {rule.name}\n"
        f"# Path: {rule.path_pattern}\n"
        f"# Limit: {rule.requests} requests / {rule.window_seconds}s per {rule.scope.value}\n"
        f"# Action: {rule.action.value}\n"
        f"# --------------------------------------------------------\n"
        f"\n"
        f"# Place in http {{ }} context:\n"
        f"limit_req_zone $binary_remote_addr "
        f"zone={zone}:{zone_size_mb}m "
        f"rate={rate};\n"
        f"\n"
        f"# Place in location {rule.path_pattern} {{ }} block:\n"
        f"{action_comment}\n"
        f"limit_req zone={zone} burst={burst} nodelay;\n"
        f"{status_line}\n"
    )


def export_pack_nginx(pack: "RateLimitRulepack", zone_size_mb: int = 10) -> str:
    """
    Export an entire RateLimitRulepack as a combined Nginx config snippet.

    All limit_req_zone declarations are placed first (http{} context),
    followed by per-location limit_req blocks grouped by rule.

    Args:
        pack:          The rulepack to export.
        zone_size_mb:  Shared memory zone size per rule in MB.

    Returns:
        Multi-line Nginx configuration string.
    """
    lines: list[str] = [
        f"# ========================================================\n"
        f"# waf-defense-rulepacks — Nginx export\n"
        f"# Pack: {pack.name}\n"
        f"# Rules: {len(pack.rules)}\n"
        f"# ========================================================\n",
    ]
    for rule in pack.rules:
        lines.append(generate_nginx_rate_limit(rule, zone_size_mb=zone_size_mb))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# ModSecurity
# ---------------------------------------------------------------------------

def generate_modsec_rule(
    rule: "RateLimitRule",
    rule_id_base: int = 9000000,
) -> str:
    """
    Generate a ModSecurity 2.x SecAction + SecRule snippet for rate limiting.

    Uses the ip.* variable namespace with initcol/setvar/expirevar to implement
    a sliding-window counter per source IP.  Requires mod_security2 with
    collection support (standard in OWASP CRS setups).

    Rule IDs must not collide with CRS rules (1000000–9999999 range for custom).
    Use rule_id_base to assign a unique starting ID per rule.

    Args:
        rule:          The RateLimitRule to convert.
        rule_id_base:  Base rule ID for the two generated SecAction/SecRule
                       entries.  Default 9000000; increment by 2 per rule.

    Returns:
        Multi-line ModSecurity configuration string.
    """
    zone = _zone_name(rule)
    counter_var = f"ip.k1n_{zone}_count"
    counter_tag = f"k1n_{zone}_count".upper()

    if rule.action == RateLimitAction.BLOCK:
        action_directive = "deny,status:429"
    elif rule.action == RateLimitAction.LOG:
        action_directive = "pass,log"
    else:
        action_directive = "redirect:/challenge,status:302"

    return (
        f"# --------------------------------------------------------\n"
        f"# waf-defense-rulepacks — ModSecurity rate-limit stub\n"
        f"# Rule: {rule.name}\n"
        f"# Path: {rule.path_pattern}\n"
        f"# Limit: {rule.requests} requests / {rule.window_seconds}s per {rule.scope.value}\n"
        f"# Action: {rule.action.value}\n"
        f"# IDs: {rule_id_base} (counter init), {rule_id_base + 1} (threshold check)\n"
        f"# --------------------------------------------------------\n"
        f"\n"
        f"# Step 1 — initialise IP collection and increment counter\n"
        f'SecAction \\\n'
        f'  "id:{rule_id_base},\\\n'
        f'   phase:1,\\\n'
        f'   pass,\\\n'
        f'   nolog,\\\n'
        f'   initcol:ip=%{{REMOTE_ADDR}},\\\n'
        f'   setvar:{counter_var}=+1,\\\n'
        f'   expirevar:{counter_var}={rule.window_seconds}"\n'
        f"\n"
        f"# Step 2 — block/log when counter exceeds the threshold\n"
        f'SecRule {counter_tag} "@gt {rule.requests}" \\\n'
        f'  "id:{rule_id_base + 1},\\\n'
        f'   phase:2,\\\n'
        f'   {action_directive},\\\n'
        f'   msg:\'Rate limit exceeded: {rule.name}\',\\\n'
        f'   logdata:\'Requests: %{{{counter_tag}}}\',\\\n'
        f'   tag:\'k1n-waf/rate-limit\'"\n'
    )


def export_pack_modsec(
    pack: "RateLimitRulepack",
    rule_id_start: int = 9000000,
    id_step: int = 2,
) -> str:
    """
    Export an entire RateLimitRulepack as a ModSecurity configuration snippet.

    Each rule consumes two IDs (SecAction + SecRule); IDs are assigned
    sequentially from rule_id_start.

    Args:
        pack:           The rulepack to export.
        rule_id_start:  First rule ID to assign (default 9000000).
        id_step:        IDs consumed per rule (default 2).

    Returns:
        Multi-line ModSecurity configuration string.
    """
    lines: list[str] = [
        f"# ========================================================\n"
        f"# waf-defense-rulepacks — ModSecurity export\n"
        f"# Pack: {pack.name}\n"
        f"# Rules: {len(pack.rules)}\n"
        f"# ========================================================\n",
    ]
    for i, rule in enumerate(pack.rules):
        rule_id = rule_id_start + i * id_step
        lines.append(generate_modsec_rule(rule, rule_id_base=rule_id))
    return "\n".join(lines)
