"""
CLI para inventariar a cobertura de packs WAF do repositório.

O objetivo é facilitar a vida de profissionais que precisam responder rápido:
- quais vendors já têm baseline pronta;
- quais categorias estão mais maduras;
- onde ainda existem lacunas antes de um rollout multivendor.
"""
from __future__ import annotations

import json
from pathlib import Path

import click

from shared.validators.pack_catalog import build_pack_catalog


@click.command("waf-catalog")
@click.option(
    "--repo-root",
    default=".",
    show_default=True,
    type=click.Path(file_okay=False, path_type=Path),
    help="Repository root that contains the WAF packs.",
)
@click.option(
    "--format",
    "output_format",
    default="summary",
    show_default=True,
    type=click.Choice(["summary", "json", "markdown"], case_sensitive=False),
    help="Output format for the generated catalog.",
)
@click.option(
    "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Optional file path to write the catalog output.",
)
def waf_catalog_cmd(repo_root: Path, output_format: str, output: Path | None) -> None:
    """Generate a catalog of the pack coverage that exists in the repository."""
    catalog = build_pack_catalog(repo_root.resolve())

    if output_format == "json":
        rendered = json.dumps(catalog.as_dict(), indent=2)
    elif output_format == "markdown":
        rendered = catalog.to_markdown()
    else:
        lines = [
            f"Total packs: {catalog.total_packs}",
            f"Vendors covered: {len(catalog.vendors)}",
            f"Missing vendors: {', '.join(catalog.missing_vendors) if catalog.missing_vendors else 'none'}",
            "",
            "Vendor counts:",
        ]
        for vendor, count in catalog.vendors.items():
            lines.append(f"  - {vendor}: {count}")
        lines.append("")
        lines.append("Category counts:")
        for category, count in catalog.categories.items():
            lines.append(f"  - {category}: {count}")
        rendered = "\n".join(lines)

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")
        click.echo(f"Wrote catalog to {output}")
        return

    click.echo(rendered)


if __name__ == "__main__":
    waf_catalog_cmd()
