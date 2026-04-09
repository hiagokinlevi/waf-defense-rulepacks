"""
`waf-export` CLI Command
=========================
Exports all built-in rate-limit rulepacks in the vendor-specific format
requested — Cloudflare JSON, AWS WAF JSON, Azure WAF JSON, Nginx conf, or
ModSecurity conf — and writes them to an output directory.

Usage:
    python -m cli.waf_export_cmd --vendor cloudflare
    python -m cli.waf_export_cmd --vendor all --output-dir ./exports
    python -m cli.waf_export_cmd --vendor nginx --pack login-bruteforce --stdout
    python -m cli.waf_export_cmd --vendor modsec --dry-run

Entry point (add to pyproject.toml [project.scripts]):
    waf-export = cli.waf_export_cmd:waf_export_cmd
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Optional

import click

from shared.rulepacks.rate_limit_rulepack import (
    RateLimitRulepack,
    build_api_protection_pack,
    build_login_bruteforce_pack,
    generate_aws_waf,
    generate_azure_waf,
    generate_cloudflare,
)
from shared.rulepacks.nginx_modsec_stubs import (
    export_pack_modsec,
    export_pack_nginx,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Supported vendor names and their canonical output file extension
_VENDOR_EXTENSIONS: dict[str, str] = {
    "cloudflare": "json",
    "aws":        "json",
    "azure":      "json",
    "nginx":      "conf",
    "modsec":     "conf",
}

#: Human-readable labels for vendor display
_VENDOR_LABELS: dict[str, str] = {
    "cloudflare": "Cloudflare WAF",
    "aws":        "AWS WAF",
    "azure":      "Azure WAF",
    "nginx":      "Nginx (ngx_http_limit_req_module)",
    "modsec":     "ModSecurity 2.x (CRS-compatible)",
}

#: All known vendor keys
_ALL_VENDORS = list(_VENDOR_EXTENSIONS.keys())


# ---------------------------------------------------------------------------
# Pack registry
# ---------------------------------------------------------------------------

def _all_packs() -> dict[str, RateLimitRulepack]:
    """Return all built-in rulepacks keyed by CLI name."""
    return {
        "login-bruteforce": build_login_bruteforce_pack(),
        "api-protection":   build_api_protection_pack(),
    }


# ---------------------------------------------------------------------------
# Per-vendor export helpers
# ---------------------------------------------------------------------------

def _export_json_pack(pack: RateLimitRulepack, vendor: str) -> str:
    """Serialise a rulepack to JSON for Cloudflare, AWS WAF, or Azure WAF."""
    _generators = {
        "cloudflare": generate_cloudflare,
        "aws":        generate_aws_waf,
        "azure":      generate_azure_waf,
    }
    gen = _generators[vendor]
    rules_out: list[Any] = [gen(rule) for rule in pack.rules]
    payload = {
        "pack_name": pack.name,
        "vendor":    vendor,
        "rules":     rules_out,
        "rule_count": len(rules_out),
    }
    return json.dumps(payload, indent=2)


def _export_pack(pack: RateLimitRulepack, vendor: str) -> str:
    """Dispatch to the correct exporter for the given vendor."""
    if vendor in ("cloudflare", "aws", "azure"):
        return _export_json_pack(pack, vendor)
    elif vendor == "nginx":
        return export_pack_nginx(pack)
    elif vendor == "modsec":
        return export_pack_modsec(pack)
    else:
        raise ValueError(f"Unsupported vendor: {vendor}")


def _output_filename(vendor: str, pack_name: str) -> str:
    """Build the output file name for a vendor + pack combination."""
    safe_pack = pack_name.replace(" ", "_").replace("/", "_")
    ext = _VENDOR_EXTENSIONS.get(vendor, "txt")
    return f"{vendor}_{safe_pack}.{ext}"


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------

@click.command("waf-export")
@click.option(
    "--vendor",
    default="cloudflare",
    type=click.Choice([*_ALL_VENDORS, "all"], case_sensitive=False),
    show_default=True,
    help=(
        "Target WAF platform to generate config for. "
        "'all' exports every supported vendor."
    ),
)
@click.option(
    "--pack",
    default="all",
    type=click.Choice(["login-bruteforce", "api-protection", "all"], case_sensitive=False),
    show_default=True,
    help="Which built-in rulepack to export. 'all' exports every pack.",
)
@click.option(
    "--output-dir",
    "output_dir",
    default="./waf-export",
    show_default=True,
    type=click.Path(),
    help="Directory to write exported files into.",
)
@click.option(
    "--stdout",
    is_flag=True,
    default=False,
    help="Print exports to stdout instead of (or in addition to) writing files.",
)
@click.option(
    "--dry-run",
    "dry_run",
    is_flag=True,
    default=False,
    help="Show what would be exported without writing any files.",
)
def waf_export_cmd(
    vendor: str,
    pack: str,
    output_dir: str,
    stdout: bool,
    dry_run: bool,
) -> None:
    """
    Export WAF rate-limit rulepacks to vendor-specific configuration formats.

    Generates Cloudflare, AWS WAF, Azure WAF, Nginx, or ModSecurity
    configuration from the built-in login-bruteforce and api-protection packs.

    Examples:

    \b
      waf-export --vendor cloudflare
      waf-export --vendor all --output-dir ./exports
      waf-export --vendor nginx --pack login-bruteforce --stdout
      waf-export --dry-run
    """
    # Resolve vendor list
    vendors: list[str] = _ALL_VENDORS if vendor == "all" else [vendor.lower()]

    # Resolve pack list
    all_packs = _all_packs()
    packs: dict[str, RateLimitRulepack] = (
        all_packs if pack == "all" else {pack: all_packs[pack]}
    )

    click.echo(
        f"Exporting {len(packs)} pack(s) for {len(vendors)} vendor(s):\n"
        f"  Packs:   {', '.join(packs.keys())}\n"
        f"  Vendors: {', '.join(_VENDOR_LABELS.get(v, v) for v in vendors)}"
    )

    if dry_run:
        click.echo("\n[DRY RUN] No files written.")
        for v in vendors:
            for pk_name in packs:
                fname = _output_filename(v, pk_name)
                click.echo(f"  Would write: {output_dir}/{fname}")
        return

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []
    errors: list[str] = []

    for v in vendors:
        for pk_name, pk in packs.items():
            try:
                content = _export_pack(pk, v)
                fname = _output_filename(v, pk_name)

                if stdout:
                    click.echo(f"\n# --- {_VENDOR_LABELS.get(v, v)} / {pk_name} ---")
                    click.echo(content)

                dest = out_path / fname
                dest.write_text(content, encoding="utf-8")
                written.append(dest)
                click.echo(f"  Written: {dest}")
            except Exception as exc:
                msg = f"Export failed for {v}/{pk_name}: {exc}"
                errors.append(msg)
                click.echo(f"  ERROR: {msg}", err=True)

    # Summary
    click.echo(
        f"\nExport complete: {len(written)} file(s) written"
        + (f", {len(errors)} error(s)" if errors else "")
        + f" → {out_path}"
    )

    if errors:
        sys.exit(1)


if __name__ == "__main__":
    waf_export_cmd()
