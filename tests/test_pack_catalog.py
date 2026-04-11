"""Testes do catálogo de packs WAF."""
from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from cli.waf_catalog_cmd import waf_catalog_cmd
from shared.validators.pack_catalog import build_pack_catalog


def _write_pack(path: Path, **overrides: str) -> None:
    """Cria um pack mínimo válido para os testes."""
    payload = {
        "name": "Catalog Test Pack",
        "vendor": "cloudflare",
        "category": "sqli_protection",
        "app_context": "generic",
        "objective": "Detect and block test traffic for pack catalog validation.",
        "risk_mitigated": "Synthetic coverage gap for tests.",
        "severity": "high",
        "mode": "block",
        "version": "1.0.0",
        "maturity": "reviewed",
    }
    payload.update(overrides)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_build_pack_catalog_counts_vendors_and_categories(tmp_path: Path) -> None:
    _write_pack(tmp_path / "cloudflare" / "waf-rules" / "block_sqli.json")
    _write_pack(
        tmp_path / "f5" / "irules" / "block_xss.json",
        vendor="f5",
        category="xss_protection",
        maturity="tested",
    )
    (tmp_path / "azure-waf").mkdir(parents=True, exist_ok=True)
    (tmp_path / "azure-waf" / "front_door_policy.json").write_text(
        json.dumps({"_k1n_metadata": {"name": "template only"}}),
        encoding="utf-8",
    )

    catalog = build_pack_catalog(tmp_path)

    assert catalog.total_packs == 2
    assert catalog.vendors["cloudflare"] == 1
    assert catalog.vendors["f5"] == 1
    assert catalog.categories["sqli_protection"] == 1
    assert catalog.categories["xss_protection"] == 1
    assert "aws-waf" in catalog.missing_vendors


def test_waf_catalog_cli_json_output(tmp_path: Path) -> None:
    _write_pack(tmp_path / "imperva" / "custom-rules" / "api_auth.json", vendor="imperva", category="api_protection")
    runner = CliRunner()

    result = runner.invoke(
        waf_catalog_cmd,
        ["--repo-root", str(tmp_path), "--format", "json"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["total_packs"] == 1
    assert payload["vendors"]["imperva"] == 1


def test_waf_catalog_cli_markdown_file_output(tmp_path: Path) -> None:
    _write_pack(tmp_path / "checkpoint" / "policies" / "admin_surface.json", vendor="checkpoint", category="access_control")
    output = tmp_path / "reports" / "catalog.md"
    runner = CliRunner()

    result = runner.invoke(
        waf_catalog_cmd,
        ["--repo-root", str(tmp_path), "--format", "markdown", "--output", str(output)],
    )

    assert result.exit_code == 0
    assert output.exists()
    contents = output.read_text(encoding="utf-8")
    assert "# WAF Pack Catalog" in contents
    assert "| checkpoint | 1 |" in contents
