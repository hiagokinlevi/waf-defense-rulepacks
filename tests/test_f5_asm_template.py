# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) 2026 Hiago Kin Levi
from __future__ import annotations

import json
from pathlib import Path

from shared.validators.pack_catalog import build_pack_catalog
from shared.validators.validate_pack import validate_pack


REPO_ROOT = Path(__file__).parent.parent
TEMPLATE_PATH = REPO_ROOT / "f5" / "asm" / "policy_export_template.json"


def test_f5_asm_template_is_present_and_skipped_by_validator() -> None:
    """Container templates should stay parseable without being treated as packs."""
    assert TEMPLATE_PATH.exists()
    assert validate_pack(TEMPLATE_PATH) == []


def test_f5_asm_template_uses_safe_rollout_defaults() -> None:
    """The template should default to transparent enforcement and learning."""
    payload = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
    metadata = payload["_k1n_metadata"]
    policy = payload["policy"]

    assert metadata["vendor"] == "f5"
    assert metadata["maturity"] == "reviewed"
    assert "transparent mode" in metadata["deployment_notes"].lower()

    assert policy["template"]["name"] == "POLICY_TEMPLATE_FUNDAMENTAL"
    assert policy["enforcementMode"] == "transparent"
    assert policy["signature-staging"] is True
    assert policy["policy-builder"]["learningMode"] == "automatic"

    violations = {
        entry["name"]: entry for entry in policy["blocking-settings"]["violations"]
    }
    assert violations["VIOL_ATTACK_SIGNATURE_DETECTED"]["block"] is False
    assert violations["VIOL_EVASION_DETECTED"]["alarm"] is True
    assert violations["VIOL_URL"]["learn"] is True


def test_f5_asm_template_is_not_counted_in_pack_catalog() -> None:
    """Catalog output should continue to count only standalone packs."""
    catalog = build_pack_catalog(REPO_ROOT)
    paths = {record.path for record in catalog.records}

    assert "f5/asm/policy_export_template.json" not in paths
