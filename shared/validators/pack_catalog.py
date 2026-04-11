"""
Constrói um catálogo resumido dos packs WAF disponíveis no repositório.

Este módulo existe para ajudar equipes a responder rapidamente perguntas como:
- quais vendors já possuem cobertura prática;
- quais categorias têm mais ou menos packs;
- quais itens ainda estão em draft versus tested/operational.

A saída é intencionalmente simples para ser reutilizada em CLI, documentação
e automações futuras sem depender de um backend externo.
"""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


EXPECTED_VENDORS = (
    "cloudflare",
    "aws-waf",
    "azure-waf",
    "f5",
    "fortiweb",
    "imperva",
    "checkpoint",
    "modsecurity",
    "nginx",
    "generic",
)

REQUIRED_FIELDS = (
    "name",
    "vendor",
    "category",
    "objective",
    "risk_mitigated",
    "severity",
    "mode",
    "version",
    "maturity",
)

DEFAULT_SKIP_PATTERNS = (
    "schemas",
    "terraform",
    "examples",
    ".git",
    ".pytest_cache",
    ".venv",
    "node_modules",
    "site-packages",
)


@dataclass(frozen=True)
class PackCatalogEntry:
    """Representa um pack válido encontrado no repositório."""

    name: str
    vendor: str
    category: str
    mode: str
    maturity: str
    path: str


@dataclass(frozen=True)
class CatalogSummary:
    """Resumo agregado do catálogo para uso em CLI e relatórios."""

    total_packs: int
    vendors: dict[str, int]
    categories: dict[str, int]
    maturities: dict[str, int]
    missing_vendors: list[str]
    records: list[PackCatalogEntry]

    def as_dict(self) -> dict[str, Any]:
        """Serializa o resumo em um dicionário estável."""
        return {
            "total_packs": self.total_packs,
            "vendors": self.vendors,
            "categories": self.categories,
            "maturities": self.maturities,
            "missing_vendors": self.missing_vendors,
            "records": [asdict(record) for record in self.records],
        }

    def to_markdown(self) -> str:
        """Gera uma visão em Markdown amigável para README e relatórios."""
        lines = [
            "# WAF Pack Catalog",
            "",
            f"- Total packs: **{self.total_packs}**",
            f"- Vendors with coverage: **{len(self.vendors)}**",
            f"- Missing vendors: **{', '.join(self.missing_vendors) if self.missing_vendors else 'none'}**",
            "",
            "## Vendors",
            "",
            "| Vendor | Packs |",
            "|---|---:|",
        ]
        for vendor, count in self.vendors.items():
            lines.append(f"| {vendor} | {count} |")

        lines.extend(
            [
                "",
                "## Categories",
                "",
                "| Category | Packs |",
                "|---|---:|",
            ]
        )
        for category, count in self.categories.items():
            lines.append(f"| {category} | {count} |")

        lines.extend(
            [
                "",
                "## Maturity",
                "",
                "| Maturity | Packs |",
                "|---|---:|",
            ]
        )
        for maturity, count in self.maturities.items():
            lines.append(f"| {maturity} | {count} |")

        return "\n".join(lines)


def _should_skip(path: Path, skip_patterns: tuple[str, ...]) -> bool:
    """Retorna True para caminhos que não devem entrar no catálogo."""
    path_str = str(path)
    return any(pattern in path_str for pattern in skip_patterns)


def _looks_like_pack(document: dict[str, Any]) -> bool:
    """Diferencia packs válidos de templates ou artefatos auxiliares."""
    if "_k1n_metadata" in document and not all(field in document for field in REQUIRED_FIELDS):
        return False
    return all(field in document for field in REQUIRED_FIELDS)


def build_pack_catalog(
    repo_root: Path,
    skip_patterns: tuple[str, ...] = DEFAULT_SKIP_PATTERNS,
) -> CatalogSummary:
    """
    Lê os packs do repositório e devolve um resumo agregado.

    Args:
        repo_root: Raiz do repositório onde os packs serão procurados.
        skip_patterns: Substrings de caminho que devem ser ignoradas.
    """
    records: list[PackCatalogEntry] = []

    for json_file in sorted(repo_root.rglob("*.json")):
        if _should_skip(json_file, skip_patterns):
            continue

        try:
            document = json.loads(json_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        if not isinstance(document, dict) or not _looks_like_pack(document):
            continue

        records.append(
            PackCatalogEntry(
                name=document["name"],
                vendor=document["vendor"],
                category=document["category"],
                mode=document["mode"],
                maturity=document["maturity"],
                path=str(json_file.relative_to(repo_root)),
            )
        )

    vendor_counts = dict(sorted(Counter(record.vendor for record in records).items()))
    category_counts = dict(sorted(Counter(record.category for record in records).items()))
    maturity_counts = dict(sorted(Counter(record.maturity for record in records).items()))
    missing_vendors = sorted(vendor for vendor in EXPECTED_VENDORS if vendor not in vendor_counts)

    return CatalogSummary(
        total_packs=len(records),
        vendors=vendor_counts,
        categories=category_counts,
        maturities=maturity_counts,
        missing_vendors=missing_vendors,
        records=records,
    )
