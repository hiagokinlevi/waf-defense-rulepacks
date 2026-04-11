# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) 2026 Hiago Kin Levi
"""Tests for shared/rulepacks/host_header_attack_pack.py."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.rulepacks.host_header_attack_pack import (
    HostHeaderAttackPack,
    HostHeaderEvalResult,
    HostHeaderFinding,
    HostHeaderRequest,
    _CHECK_WEIGHTS,
)


def _pack(block_on_severity: str = "HIGH") -> HostHeaderAttackPack:
    return HostHeaderAttackPack(block_on_severity=block_on_severity)


def _req(url: str = "https://app.example.com/login", headers: dict[str, str] | None = None) -> HostHeaderRequest:
    return HostHeaderRequest(url=url, headers=headers or {})


def _ids(result: HostHeaderEvalResult) -> set[str]:
    return {finding.check_id for finding in result.findings}


def _has(result: HostHeaderEvalResult, check_id: str) -> bool:
    return check_id in _ids(result)


def test_clean_request_has_no_findings() -> None:
    result = _pack().evaluate(_req(headers={"Host": "app.example.com"}))
    assert result.findings == []
    assert result.risk_score == 0
    assert result.blocked is False


def test_hho001_multiple_host_headers_fire() -> None:
    result = _pack().evaluate(
        _req(headers={"Host": "app.example.com", "X-Forwarded-Host": "edge.example.com"})
    )
    assert _has(result, "HHO-001")


def test_hho002_absolute_url_in_host_fires() -> None:
    result = _pack().evaluate(_req(headers={"Host": "https://evil.example/redirect"}))
    assert _has(result, "HHO-002")


def test_hho003_private_ip_target_fires() -> None:
    result = _pack().evaluate(_req(headers={"Host": "169.254.169.254"}))
    assert _has(result, "HHO-003")
    assert result.blocked is True


def test_hho003_metadata_hostname_fires() -> None:
    result = _pack().evaluate(_req(headers={"X-Forwarded-Host": "metadata.google.internal"}))
    assert _has(result, "HHO-003")


def test_hho003_decimal_localhost_alias_fires() -> None:
    result = _pack().evaluate(_req(headers={"Host": "2130706433"}))
    assert _has(result, "HHO-003")
    assert result.blocked is True


def test_hho003_hex_metadata_alias_fires() -> None:
    result = _pack().evaluate(_req(headers={"Host": "0xA9FEA9FE"}))
    assert _has(result, "HHO-003")
    assert result.blocked is True


def test_hho004_invalid_chars_fire() -> None:
    result = _pack().evaluate(_req(headers={"Host": "app.example.com/admin"}))
    assert _has(result, "HHO-004")


def test_hho004_encoded_value_fires() -> None:
    result = _pack().evaluate(_req(headers={"Host": "app.example.com%2fadmin"}))
    assert _has(result, "HHO-004")


def test_hho005_external_mismatch_fires() -> None:
    result = _pack().evaluate(
        _req(headers={"Host": "app.example.com", "X-Forwarded-Host": "evil.example.net"})
    )
    assert _has(result, "HHO-005")


def test_hho005_same_external_host_does_not_fire() -> None:
    result = _pack().evaluate(
        _req(headers={"Host": "app.example.com", "X-Forwarded-Host": "app.example.com"})
    )
    assert not _has(result, "HHO-005")


def test_hho006_multiple_values_in_single_header_fire() -> None:
    result = _pack().evaluate(_req(headers={"X-Forwarded-Host": "app.example.com,evil.example.net"}))
    assert _has(result, "HHO-006")


def test_hho007_ip_literal_override_fires() -> None:
    result = _pack().evaluate(
        _req(url="https://portal.example.com/", headers={"Host": "8.8.8.8"})
    )
    assert _has(result, "HHO-007")


def test_hho007_hex_public_ip_literal_override_fires() -> None:
    result = _pack().evaluate(
        _req(url="https://portal.example.com/", headers={"Host": "0x08080808"})
    )
    assert _has(result, "HHO-007")


def test_forwarded_header_host_value_is_parsed() -> None:
    result = _pack().evaluate(
        _req(headers={"Host": "app.example.com", "Forwarded": "for=1.2.3.4;host=evil.example.net;proto=https"})
    )
    assert _has(result, "HHO-001")
    assert _has(result, "HHO-005")


def test_risk_score_caps_at_100() -> None:
    result = _pack().evaluate(
        _req(
            url="https://portal.example.com/",
            headers={
                "Host": "https://169.254.169.254/admin",
                "X-Forwarded-Host": "evil.example.net,metadata.google.internal",
            },
        )
    )
    assert result.risk_score == 100


def test_block_threshold_critical_allows_medium_only() -> None:
    result = _pack(block_on_severity="CRITICAL").evaluate(
        _req(url="https://portal.example.com/", headers={"Host": "8.8.8.8"})
    )
    assert _has(result, "HHO-007")
    assert result.blocked is False


def test_summary_contains_block_state() -> None:
    result = _pack().evaluate(_req(headers={"Host": "localhost"}))
    assert "BLOCKED" in result.summary()


def test_to_dict_serializes_models() -> None:
    result = _pack().evaluate(_req(headers={"Host": "localhost"}))
    payload = result.to_dict()
    assert payload["blocked"] is True
    assert payload["findings"][0]["check_id"] == "HHO-003"


def test_evaluate_many_preserves_order() -> None:
    results = _pack().evaluate_many(
        [
            _req(headers={"Host": "app.example.com"}),
            _req(headers={"Host": "localhost"}),
        ]
    )
    assert len(results) == 2
    assert results[0].blocked is False
    assert results[1].blocked is True


def test_weight_catalog_is_stable() -> None:
    assert _CHECK_WEIGHTS["HHO-003"] == 45


def test_invalid_threshold_raises() -> None:
    with pytest.raises(ValueError):
        HostHeaderAttackPack(block_on_severity="SEVERE")


def test_finding_type_is_returned() -> None:
    result = _pack().evaluate(_req(headers={"Host": "localhost"}))
    assert isinstance(result.findings[0], HostHeaderFinding)
