# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) 2026 Hiago Kin Levi
"""
Tests for shared/rulepacks/ssrf_protection_pack.py

Covers:
  - All seven SSRF check IDs (SSRF-001 through SSRF-007)
  - Clean-request baseline (no findings)
  - Values detected in query params, body, and headers
  - blocked / not-blocked logic with various block_on_severity settings
  - risk_score computation and cap at 100
  - evaluate_many() batch evaluation
  - to_dict() serialisation on all dataclasses
  - Custom block_on_severity thresholds
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Set

import pytest

# Ensure the repo root is on sys.path so imports work regardless of cwd
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.rulepacks.ssrf_protection_pack import (
    HTTPRequest,
    SSRFEvalResult,
    SSRFFinding,
    SSRFProtectionPack,
    _CHECK_WEIGHTS,
    _extract_values,
)


# ===========================================================================
# Factories / helpers
# ===========================================================================

def _pack(block_on_severity: str = "HIGH") -> SSRFProtectionPack:
    """Return a pack instance with the given block threshold."""
    return SSRFProtectionPack(block_on_severity=block_on_severity)


def _req(
    url: str = "https://example.com/fetch",
    method: str = "GET",
    query_params: dict | None = None,
    body: str | None = None,
    headers: dict | None = None,
    source_ip: str | None = None,
) -> HTTPRequest:
    """Convenience factory for HTTPRequest."""
    return HTTPRequest(
        url=url,
        method=method,
        query_params=query_params or {},
        body=body,
        headers=headers or {},
        source_ip=source_ip,
    )


def _check_ids(result: SSRFEvalResult) -> Set[str]:
    """Extract the set of fired check IDs from a result."""
    return {f.check_id for f in result.findings}


def _has(result: SSRFEvalResult, check_id: str) -> bool:
    return check_id in _check_ids(result)


# ===========================================================================
# 1. Clean request — no findings
# ===========================================================================

class TestCleanRequest:
    def test_empty_params_no_findings(self):
        result = _pack().evaluate(_req())
        assert result.findings == []

    def test_public_url_no_findings(self):
        result = _pack().evaluate(
            _req(query_params={"url": "https://api.example.com/data"})
        )
        assert not _has(result, "SSRF-001")
        assert not _has(result, "SSRF-002")
        assert not _has(result, "SSRF-003")

    def test_risk_score_zero_on_clean(self):
        result = _pack().evaluate(_req())
        assert result.risk_score == 0

    def test_blocked_false_on_clean(self):
        result = _pack().evaluate(_req())
        assert result.blocked is False

    def test_public_ip_no_finding(self):
        # 8.8.8.8 must NOT trigger SSRF-001
        result = _pack().evaluate(_req(query_params={"dns": "8.8.8.8"}))
        assert not _has(result, "SSRF-001")

    def test_regular_body_no_finding(self):
        result = _pack().evaluate(
            _req(body='{"action":"search","query":"widgets"}')
        )
        assert result.findings == []

    def test_normal_domain_no_ssrf007(self):
        result = _pack().evaluate(
            _req(query_params={"host": "example.com"})
        )
        assert not _has(result, "SSRF-007")

    def test_http_scheme_no_finding(self):
        result = _pack().evaluate(
            _req(query_params={"callback": "http://external.example.com/hook"})
        )
        assert not _has(result, "SSRF-005")

    def test_https_scheme_no_finding(self):
        result = _pack().evaluate(
            _req(query_params={"callback": "https://external.example.com/hook"})
        )
        assert not _has(result, "SSRF-005")

    def test_public_long_url_no_shortener(self):
        result = _pack().evaluate(
            _req(query_params={"redirect": "https://www.example.com/very-long-path/to/resource"})
        )
        assert not _has(result, "SSRF-006")


# ===========================================================================
# 2. SSRF-001 — RFC 1918 private IP
# ===========================================================================

class TestSSRF001PrivateIP:
    def test_10_x_in_query_triggers(self):
        result = _pack().evaluate(_req(query_params={"host": "10.0.0.1"}))
        assert _has(result, "SSRF-001")

    def test_10_x_full_range_triggers(self):
        result = _pack().evaluate(_req(query_params={"ip": "10.255.255.255"}))
        assert _has(result, "SSRF-001")

    def test_172_16_triggers(self):
        result = _pack().evaluate(_req(query_params={"target": "172.16.0.1"}))
        assert _has(result, "SSRF-001")

    def test_172_31_triggers(self):
        result = _pack().evaluate(_req(query_params={"target": "172.31.255.254"}))
        assert _has(result, "SSRF-001")

    def test_172_32_does_not_trigger(self):
        # 172.32.x.x is outside RFC 1918
        result = _pack().evaluate(_req(query_params={"target": "172.32.0.1"}))
        assert not _has(result, "SSRF-001")

    def test_172_15_does_not_trigger(self):
        # 172.15.x.x is outside RFC 1918
        result = _pack().evaluate(_req(query_params={"target": "172.15.0.1"}))
        assert not _has(result, "SSRF-001")

    def test_192_168_triggers(self):
        result = _pack().evaluate(_req(query_params={"url": "http://192.168.1.100/admin"}))
        assert _has(result, "SSRF-001")

    def test_8_8_8_8_does_not_trigger(self):
        result = _pack().evaluate(_req(query_params={"dns": "8.8.8.8"}))
        assert not _has(result, "SSRF-001")

    def test_private_ip_in_url_string_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"url": "http://10.1.2.3/internal-api"})
        )
        assert _has(result, "SSRF-001")

    def test_severity_is_critical(self):
        result = _pack().evaluate(_req(query_params={"host": "10.0.0.1"}))
        finding = next(f for f in result.findings if f.check_id == "SSRF-001")
        assert finding.severity == "CRITICAL"

    def test_weight_applied_to_score(self):
        result = _pack().evaluate(_req(query_params={"host": "10.0.0.1"}))
        assert result.risk_score == _CHECK_WEIGHTS["SSRF-001"]


# ===========================================================================
# 3. SSRF-002 — Localhost / loopback
# ===========================================================================

class TestSSRF002Loopback:
    def test_localhost_triggers(self):
        result = _pack().evaluate(_req(query_params={"url": "http://localhost/admin"}))
        assert _has(result, "SSRF-002")

    def test_localhost_uppercase_triggers(self):
        result = _pack().evaluate(_req(query_params={"url": "LOCALHOST"}))
        assert _has(result, "SSRF-002")

    def test_127_0_0_1_triggers(self):
        result = _pack().evaluate(_req(query_params={"server": "127.0.0.1"}))
        assert _has(result, "SSRF-002")

    def test_127_0_0_254_triggers(self):
        result = _pack().evaluate(_req(query_params={"server": "127.0.0.254"}))
        assert _has(result, "SSRF-002")

    def test_ipv6_loopback_triggers(self):
        result = _pack().evaluate(_req(query_params={"addr": "::1"}))
        assert _has(result, "SSRF-002")

    def test_all_zeros_triggers(self):
        result = _pack().evaluate(_req(query_params={"bind": "0.0.0.0"}))
        assert _has(result, "SSRF-002")

    def test_severity_is_critical(self):
        result = _pack().evaluate(_req(query_params={"url": "http://localhost/"}))
        finding = next(f for f in result.findings if f.check_id == "SSRF-002")
        assert finding.severity == "CRITICAL"

    def test_random_hostname_does_not_trigger(self):
        result = _pack().evaluate(_req(query_params={"host": "notlocalhost.example.com"}))
        assert not _has(result, "SSRF-002")


# ===========================================================================
# 4. SSRF-003 — Cloud metadata endpoint
# ===========================================================================

class TestSSRF003Metadata:
    def test_aws_imds_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"url": "http://169.254.169.254/latest/meta-data/"})
        )
        assert _has(result, "SSRF-003")

    def test_aws_imds_bare_ip_triggers(self):
        result = _pack().evaluate(_req(query_params={"host": "169.254.169.254"}))
        assert _has(result, "SSRF-003")

    def test_gcp_metadata_internal_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"svc": "http://metadata.google.internal/computeMetadata/v1/"})
        )
        assert _has(result, "SSRF-003")

    def test_gcp_metadata_uppercase_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"svc": "METADATA.GOOGLE.INTERNAL"})
        )
        assert _has(result, "SSRF-003")

    def test_ecs_credentials_triggers(self):
        result = _pack().evaluate(_req(query_params={"url": "169.254.170.2/creds"}))
        assert _has(result, "SSRF-003")

    def test_ipv6_metadata_triggers(self):
        result = _pack().evaluate(_req(query_params={"addr": "fd00:ec2::254"}))
        assert _has(result, "SSRF-003")

    def test_severity_is_critical(self):
        result = _pack().evaluate(_req(query_params={"url": "169.254.169.254"}))
        finding = next(f for f in result.findings if f.check_id == "SSRF-003")
        assert finding.severity == "CRITICAL"

    def test_unrelated_169_ip_no_trigger(self):
        # 169.254.1.1 is link-local but not a metadata IP — should NOT fire SSRF-003
        # (only specific metadata IPs are checked)
        result = _pack().evaluate(_req(query_params={"addr": "169.254.1.1"}))
        assert not _has(result, "SSRF-003")


# ===========================================================================
# 5. SSRF-004 — DNS rebinding indicator
# ===========================================================================

class TestSSRF004DNSRebind:
    def test_nip_io_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"host": "10-0-0-1.nip.io"})
        )
        assert _has(result, "SSRF-004")

    def test_nip_io_in_url_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"url": "http://192-168-1-1.nip.io/secret"})
        )
        assert _has(result, "SSRF-004")

    def test_xip_io_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"host": "10.0.0.1.xip.io"})
        )
        assert _has(result, "SSRF-004")

    def test_sslip_io_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"host": "192.168.0.1.sslip.io"})
        )
        assert _has(result, "SSRF-004")

    def test_traefik_me_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"host": "app.traefik.me"})
        )
        assert _has(result, "SSRF-004")

    def test_localtest_me_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"callback": "http://myapp.localtest.me/hook"})
        )
        assert _has(result, "SSRF-004")

    def test_lvh_me_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"url": "http://app.lvh.me/"})
        )
        assert _has(result, "SSRF-004")

    def test_severity_is_high(self):
        result = _pack().evaluate(_req(query_params={"host": "evil.nip.io"}))
        finding = next(f for f in result.findings if f.check_id == "SSRF-004")
        assert finding.severity == "HIGH"

    def test_normal_domain_does_not_trigger(self):
        result = _pack().evaluate(
            _req(query_params={"host": "example.com"})
        )
        assert not _has(result, "SSRF-004")

    def test_legitimate_io_domain_no_trigger(self):
        # A valid .io domain that is not a rebinding service
        result = _pack().evaluate(
            _req(query_params={"host": "myapp.io"})
        )
        assert not _has(result, "SSRF-004")


# ===========================================================================
# 6. SSRF-005 — Dangerous URL scheme
# ===========================================================================

class TestSSRF005Scheme:
    def test_file_scheme_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"url": "file:///etc/passwd"})
        )
        assert _has(result, "SSRF-005")

    def test_gopher_scheme_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"url": "gopher://evil.example.com:70/_GET /"})
        )
        assert _has(result, "SSRF-005")

    def test_ftp_scheme_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"url": "ftp://internal.corp/files/"})
        )
        assert _has(result, "SSRF-005")

    def test_dict_scheme_triggers(self):
        result = _pack().evaluate(_req(query_params={"url": "dict://localhost:11211/"}))
        assert _has(result, "SSRF-005")

    def test_sftp_scheme_triggers(self):
        result = _pack().evaluate(_req(query_params={"url": "sftp://server/path"}))
        assert _has(result, "SSRF-005")

    def test_ldap_scheme_triggers(self):
        result = _pack().evaluate(_req(query_params={"url": "ldap://corp.internal/"}))
        assert _has(result, "SSRF-005")

    def test_smtp_scheme_triggers(self):
        result = _pack().evaluate(_req(query_params={"url": "smtp://mail.internal/"}))
        assert _has(result, "SSRF-005")

    def test_tftp_scheme_triggers(self):
        result = _pack().evaluate(_req(query_params={"url": "tftp://10.0.0.1/config"}))
        assert _has(result, "SSRF-005")

    def test_http_scheme_does_not_trigger(self):
        result = _pack().evaluate(
            _req(query_params={"url": "http://api.example.com/endpoint"})
        )
        assert not _has(result, "SSRF-005")

    def test_https_scheme_does_not_trigger(self):
        result = _pack().evaluate(
            _req(query_params={"url": "https://api.example.com/endpoint"})
        )
        assert not _has(result, "SSRF-005")

    def test_severity_is_high(self):
        result = _pack().evaluate(_req(query_params={"url": "file:///etc/hosts"}))
        finding = next(f for f in result.findings if f.check_id == "SSRF-005")
        assert finding.severity == "HIGH"

    def test_value_without_scheme_no_trigger(self):
        result = _pack().evaluate(_req(query_params={"name": "some-plain-value"}))
        assert not _has(result, "SSRF-005")


# ===========================================================================
# 7. SSRF-006 — URL shortener / redirect service
# ===========================================================================

class TestSSRF006Shortener:
    def test_bitly_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"redirect": "https://bit.ly/3xYzAb"})
        )
        assert _has(result, "SSRF-006")

    def test_t_co_triggers(self):
        result = _pack().evaluate(_req(query_params={"link": "https://t.co/AbC123"}))
        assert _has(result, "SSRF-006")

    def test_tinyurl_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"url": "http://tinyurl.com/y4k7c2b"})
        )
        assert _has(result, "SSRF-006")

    def test_goo_gl_triggers(self):
        result = _pack().evaluate(_req(query_params={"link": "https://goo.gl/maps/xyz"}))
        assert _has(result, "SSRF-006")

    def test_owly_triggers(self):
        result = _pack().evaluate(_req(query_params={"url": "http://ow.ly/abc123"}))
        assert _has(result, "SSRF-006")

    def test_is_gd_triggers(self):
        result = _pack().evaluate(_req(query_params={"u": "https://is.gd/xyz123"}))
        assert _has(result, "SSRF-006")

    def test_buffly_triggers(self):
        result = _pack().evaluate(_req(query_params={"url": "https://buff.ly/3aBcDeF"}))
        assert _has(result, "SSRF-006")

    def test_adf_ly_triggers(self):
        result = _pack().evaluate(_req(query_params={"link": "https://adf.ly/12345"}))
        assert _has(result, "SSRF-006")

    def test_tiny_cc_triggers(self):
        result = _pack().evaluate(_req(query_params={"redirect": "http://tiny.cc/ab1"}))
        assert _has(result, "SSRF-006")

    def test_full_url_does_not_trigger(self):
        result = _pack().evaluate(
            _req(query_params={"url": "https://www.example.com/products/widget-pro-2000"})
        )
        assert not _has(result, "SSRF-006")

    def test_severity_is_medium(self):
        result = _pack().evaluate(_req(query_params={"url": "https://bit.ly/xyz"}))
        finding = next(f for f in result.findings if f.check_id == "SSRF-006")
        assert finding.severity == "MEDIUM"


# ===========================================================================
# 8. SSRF-007 — Internal service hostname
# ===========================================================================

class TestSSRF007InternalHost:
    def test_internal_tld_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"host": "api-service.internal/endpoint"})
        )
        assert _has(result, "SSRF-007")

    def test_local_tld_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"host": "printer.local/"})
        )
        assert _has(result, "SSRF-007")

    def test_corp_tld_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"target": "intranet.corp/"})
        )
        assert _has(result, "SSRF-007")

    def test_lan_tld_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"host": "router.lan/"})
        )
        assert _has(result, "SSRF-007")

    def test_localdomain_tld_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"host": "server.localdomain/"})
        )
        assert _has(result, "SSRF-007")

    def test_redis_hostname_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"dsn": "redis://redis:6379/0"})
        )
        assert _has(result, "SSRF-007")

    def test_elasticsearch_hostname_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"es": "http://elasticsearch:9200/"})
        )
        assert _has(result, "SSRF-007")

    def test_mongodb_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"dsn": "mongodb://mongodb:27017/mydb"})
        )
        assert _has(result, "SSRF-007")

    def test_postgres_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"db": "postgres://postgres:5432/app"})
        )
        assert _has(result, "SSRF-007")

    def test_consul_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"svc": "http://consul:8500/v1/health"})
        )
        assert _has(result, "SSRF-007")

    def test_vault_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"secrets": "http://vault:8200/v1/secret/myapp"})
        )
        assert _has(result, "SSRF-007")

    def test_kafka_triggers(self):
        result = _pack().evaluate(
            _req(query_params={"broker": "kafka:9092"})
        )
        assert _has(result, "SSRF-007")

    def test_example_com_does_not_trigger(self):
        result = _pack().evaluate(
            _req(query_params={"host": "example.com"})
        )
        assert not _has(result, "SSRF-007")

    def test_severity_is_high(self):
        result = _pack().evaluate(
            _req(query_params={"host": "db.internal/"})
        )
        finding = next(f for f in result.findings if f.check_id == "SSRF-007")
        assert finding.severity == "HIGH"


# ===========================================================================
# 9. Location detection — query / body / header
# ===========================================================================

class TestValueLocations:
    def test_private_ip_in_query_location_is_query(self):
        result = _pack().evaluate(_req(query_params={"target": "10.0.0.1"}))
        finding = next(f for f in result.findings if f.check_id == "SSRF-001")
        assert finding.param_location == "query"

    def test_private_ip_in_body_triggers(self):
        result = _pack().evaluate(_req(body='{"url":"http://192.168.1.1/data"}'))
        assert _has(result, "SSRF-001")

    def test_private_ip_in_body_location_is_body(self):
        result = _pack().evaluate(_req(body='redirect=http://10.0.0.1/'))
        finding = next(f for f in result.findings if f.check_id == "SSRF-001")
        assert finding.param_location == "body"

    def test_localhost_in_header_triggers(self):
        result = _pack().evaluate(_req(headers={"X-Forwarded-Host": "localhost"}))
        assert _has(result, "SSRF-002")

    def test_localhost_in_header_location_is_header(self):
        result = _pack().evaluate(_req(headers={"X-Target": "http://localhost/admin"}))
        finding = next(f for f in result.findings if f.check_id == "SSRF-002")
        assert finding.param_location == "header"

    def test_metadata_in_body_triggers(self):
        result = _pack().evaluate(_req(body="fetch_url=http://169.254.169.254/latest/"))
        assert _has(result, "SSRF-003")

    def test_shortener_in_header_triggers(self):
        result = _pack().evaluate(_req(headers={"Referer": "https://bit.ly/abc"}))
        assert _has(result, "SSRF-006")

    def test_dangerous_scheme_in_body_triggers(self):
        result = _pack().evaluate(_req(body='{"callback":"gopher://evil.com:9000/"}'))
        assert _has(result, "SSRF-005")

    def test_list_param_value_triggers(self):
        # query_params values may be a list of strings
        result = _pack().evaluate(
            _req(query_params={"hosts": ["external.com", "10.0.0.5"]})
        )
        assert _has(result, "SSRF-001")

    def test_none_body_no_error(self):
        result = _pack().evaluate(_req(body=None))
        assert result.findings == []

    def test_empty_headers_no_error(self):
        result = _pack().evaluate(_req(headers={}))
        assert result.findings == []


# ===========================================================================
# 10. Blocked flag logic
# ===========================================================================

class TestBlockedFlag:
    def test_critical_finding_blocks_with_high_threshold(self):
        # SSRF-001 is CRITICAL; default threshold is HIGH → should block
        result = _pack(block_on_severity="HIGH").evaluate(
            _req(query_params={"url": "http://10.0.0.1/"})
        )
        assert result.blocked is True

    def test_high_finding_blocks_with_high_threshold(self):
        result = _pack(block_on_severity="HIGH").evaluate(
            _req(query_params={"url": "file:///etc/passwd"})
        )
        assert result.blocked is True

    def test_medium_finding_does_not_block_with_high_threshold(self):
        # SSRF-006 is MEDIUM; threshold HIGH → should NOT block
        result = _pack(block_on_severity="HIGH").evaluate(
            _req(query_params={"url": "https://bit.ly/short"})
        )
        assert result.blocked is False

    def test_medium_finding_blocks_with_medium_threshold(self):
        result = _pack(block_on_severity="MEDIUM").evaluate(
            _req(query_params={"url": "https://bit.ly/short"})
        )
        assert result.blocked is True

    def test_critical_does_not_block_with_critical_threshold_on_high(self):
        # SSRF-004 (HIGH) should NOT block when threshold is CRITICAL
        result = _pack(block_on_severity="CRITICAL").evaluate(
            _req(query_params={"host": "app.nip.io"})
        )
        assert result.blocked is False

    def test_critical_finding_blocks_with_critical_threshold(self):
        result = _pack(block_on_severity="CRITICAL").evaluate(
            _req(query_params={"host": "10.0.0.1"})
        )
        assert result.blocked is True

    def test_no_findings_never_blocks(self):
        result = _pack(block_on_severity="INFO").evaluate(_req())
        assert result.blocked is False


# ===========================================================================
# 11. Risk score computation
# ===========================================================================

class TestRiskScore:
    def test_single_ssrf001_weight(self):
        result = _pack().evaluate(_req(query_params={"h": "10.0.0.1"}))
        assert result.risk_score == _CHECK_WEIGHTS["SSRF-001"]  # 45

    def test_single_ssrf006_weight(self):
        result = _pack().evaluate(_req(query_params={"u": "http://bit.ly/x"}))
        assert result.risk_score == _CHECK_WEIGHTS["SSRF-006"]  # 15

    def test_multiple_checks_sum_weights(self):
        # Trigger SSRF-002 (45) + SSRF-006 (15) = 60 if they don't overlap
        result = _pack().evaluate(
            _req(
                query_params={
                    "url": "http://bit.ly/x",
                    "host": "localhost",
                }
            )
        )
        expected = _CHECK_WEIGHTS["SSRF-002"] + _CHECK_WEIGHTS["SSRF-006"]
        assert result.risk_score == expected

    def test_risk_score_capped_at_100(self):
        # SSRF-001 (45) + SSRF-002 (45) + SSRF-006 (15) = 105 → capped at 100
        result = _pack().evaluate(
            _req(
                query_params={
                    "a": "10.0.0.1",
                    "b": "localhost",
                    "c": "http://bit.ly/x",
                }
            )
        )
        assert result.risk_score == 100

    def test_deduplication_same_check_counted_once(self):
        # Two different values both triggering SSRF-001 → weight counted once
        result = _pack().evaluate(
            _req(query_params={"a": "10.0.0.1", "b": "192.168.1.1"})
        )
        assert result.risk_score == _CHECK_WEIGHTS["SSRF-001"]

    def test_zero_score_clean_request(self):
        result = _pack().evaluate(_req())
        assert result.risk_score == 0


# ===========================================================================
# 12. evaluate_many()
# ===========================================================================

class TestEvaluateMany:
    def test_returns_list_of_correct_length(self):
        pack = _pack()
        requests = [
            _req(query_params={"url": "http://10.0.0.1/"}),
            _req(),
            _req(query_params={"url": "https://bit.ly/abc"}),
        ]
        results = pack.evaluate_many(requests)
        assert len(results) == 3

    def test_each_element_is_ssrf_eval_result(self):
        pack = _pack()
        results = pack.evaluate_many([_req(), _req(query_params={"h": "localhost"})])
        assert all(isinstance(r, SSRFEvalResult) for r in results)

    def test_clean_request_has_no_findings_in_batch(self):
        pack = _pack()
        results = pack.evaluate_many([_req()])
        assert results[0].findings == []

    def test_attack_request_has_findings_in_batch(self):
        pack = _pack()
        results = pack.evaluate_many([_req(query_params={"u": "10.0.0.1"})])
        assert _has(results[0], "SSRF-001")

    def test_empty_list_returns_empty_list(self):
        pack = _pack()
        assert pack.evaluate_many([]) == []

    def test_order_preserved(self):
        pack = _pack()
        r1 = _req(query_params={"u": "10.0.0.1"})   # will fire SSRF-001
        r2 = _req()                                    # clean
        results = pack.evaluate_many([r1, r2])
        assert _has(results[0], "SSRF-001")
        assert results[1].findings == []


# ===========================================================================
# 13. to_dict() serialisation
# ===========================================================================

class TestToDict:
    def test_http_request_to_dict_keys(self):
        req = _req(url="https://x.com", method="POST", body="data=1")
        d = req.to_dict()
        assert set(d.keys()) == {"url", "method", "headers", "query_params", "body", "source_ip"}

    def test_http_request_to_dict_values(self):
        req = HTTPRequest(
            url="https://example.com",
            method="POST",
            query_params={"k": "v"},
            body="hello",
            source_ip="1.2.3.4",
        )
        d = req.to_dict()
        assert d["url"] == "https://example.com"
        assert d["method"] == "POST"
        assert d["query_params"] == {"k": "v"}
        assert d["body"] == "hello"
        assert d["source_ip"] == "1.2.3.4"

    def test_ssrf_finding_to_dict_keys(self):
        f = SSRFFinding(
            check_id="SSRF-001",
            severity="CRITICAL",
            rule_name="RFC1918 Private IP Address",
            matched_value="10.0.0.1",
            param_location="query",
            recommendation="Block it.",
        )
        d = f.to_dict()
        assert set(d.keys()) == {
            "check_id", "severity", "rule_name",
            "matched_value", "param_location", "recommendation",
        }

    def test_ssrf_finding_to_dict_values(self):
        f = SSRFFinding(
            check_id="SSRF-002",
            severity="CRITICAL",
            rule_name="Loopback",
            matched_value="localhost",
            param_location="body",
            recommendation="Fix it.",
        )
        d = f.to_dict()
        assert d["check_id"] == "SSRF-002"
        assert d["param_location"] == "body"

    def test_ssrf_eval_result_to_dict_keys(self):
        result = _pack().evaluate(_req(query_params={"u": "http://10.0.0.1/"}))
        d = result.to_dict()
        assert set(d.keys()) == {
            "findings", "risk_score", "blocked", "summary", "by_severity"
        }

    def test_ssrf_eval_result_to_dict_findings_list(self):
        result = _pack().evaluate(_req(query_params={"u": "http://10.0.0.1/"}))
        d = result.to_dict()
        assert isinstance(d["findings"], list)
        assert len(d["findings"]) >= 1

    def test_ssrf_eval_result_to_dict_clean(self):
        result = _pack().evaluate(_req())
        d = result.to_dict()
        assert d["findings"] == []
        assert d["risk_score"] == 0
        assert d["blocked"] is False

    def test_ssrf_eval_result_to_dict_by_severity_structure(self):
        result = _pack().evaluate(_req(query_params={"u": "http://10.0.0.1/"}))
        d = result.to_dict()
        by_sev = d["by_severity"]
        assert isinstance(by_sev, dict)
        assert "CRITICAL" in by_sev


# ===========================================================================
# 14. summary() and by_severity()
# ===========================================================================

class TestSummaryAndBySeverity:
    def test_summary_blocked_string(self):
        result = _pack().evaluate(_req(query_params={"u": "http://10.0.0.1/"}))
        assert "BLOCKED" in result.summary()

    def test_summary_allowed_string(self):
        result = _pack().evaluate(_req())
        assert "ALLOWED" in result.summary()

    def test_summary_contains_risk_score(self):
        result = _pack().evaluate(_req(query_params={"u": "http://10.0.0.1/"}))
        assert "risk_score=" in result.summary()

    def test_by_severity_groups_correctly(self):
        # Trigger CRITICAL (SSRF-001) and MEDIUM (SSRF-006)
        result = _pack().evaluate(
            _req(query_params={"a": "10.0.0.1", "b": "http://bit.ly/x"})
        )
        by_sev = result.by_severity()
        assert "CRITICAL" in by_sev
        assert "MEDIUM" in by_sev

    def test_by_severity_empty_on_clean(self):
        result = _pack().evaluate(_req())
        assert result.by_severity() == {}

    def test_by_severity_order_critical_first(self):
        result = _pack().evaluate(
            _req(query_params={"a": "10.0.0.1", "b": "http://bit.ly/x"})
        )
        keys = list(result.by_severity().keys())
        assert keys.index("CRITICAL") < keys.index("MEDIUM")


# ===========================================================================
# 15. Custom block_on_severity
# ===========================================================================

class TestCustomBlockSeverity:
    def test_info_threshold_blocks_on_medium(self):
        result = _pack(block_on_severity="INFO").evaluate(
            _req(query_params={"u": "https://bit.ly/x"})
        )
        assert result.blocked is True

    def test_low_threshold_blocks_on_medium(self):
        result = _pack(block_on_severity="LOW").evaluate(
            _req(query_params={"u": "https://bit.ly/x"})
        )
        assert result.blocked is True

    def test_critical_threshold_does_not_block_on_high(self):
        result = _pack(block_on_severity="CRITICAL").evaluate(
            _req(query_params={"url": "file:///etc/passwd"})
        )
        # SSRF-005 is HIGH; threshold is CRITICAL → should not block
        assert result.blocked is False

    def test_invalid_severity_raises_value_error(self):
        with pytest.raises(ValueError):
            SSRFProtectionPack(block_on_severity="SUPER_CRITICAL")

    def test_case_insensitive_severity(self):
        # "high" (lowercase) should be accepted
        pack = SSRFProtectionPack(block_on_severity="high")
        result = pack.evaluate(_req(query_params={"u": "http://10.0.0.1/"}))
        assert result.blocked is True


# ===========================================================================
# 16. _extract_values helper
# ===========================================================================

class TestExtractValues:
    def test_query_param_str_extracted(self):
        req = _req(query_params={"k": "hello"})
        values = [v for v, _ in _extract_values(req)]
        assert "hello" in values

    def test_query_param_list_extracted_flat(self):
        req = _req(query_params={"k": ["a", "b"]})
        values = [v for v, _ in _extract_values(req)]
        assert "a" in values
        assert "b" in values

    def test_body_extracted(self):
        req = _req(body="body_content")
        values = [v for v, _ in _extract_values(req)]
        assert "body_content" in values

    def test_none_body_not_extracted(self):
        req = _req(body=None)
        values = [v for v, _ in _extract_values(req)]
        assert None not in values

    def test_header_values_extracted(self):
        req = _req(headers={"X-Custom": "header_val"})
        values = [v for v, _ in _extract_values(req)]
        assert "header_val" in values

    def test_locations_tagged_correctly(self):
        req = HTTPRequest(
            url="https://example.com",
            query_params={"p": "qval"},
            body="bval",
            headers={"X-H": "hval"},
        )
        loc_map = {v: loc for v, loc in _extract_values(req)}
        assert loc_map.get("qval") == "query"
        assert loc_map.get("bval") == "body"
        assert loc_map.get("hval") == "header"


# ===========================================================================
# 17. matched_value truncation
# ===========================================================================

class TestMatchedValueTruncation:
    def test_matched_value_max_80_chars(self):
        long_val = "http://10.0.0.1/" + "A" * 200
        result = _pack().evaluate(_req(query_params={"url": long_val}))
        for finding in result.findings:
            assert len(finding.matched_value) <= 80

    def test_matched_value_under_80_not_padded(self):
        result = _pack().evaluate(_req(query_params={"u": "10.0.0.1"}))
        finding = next(f for f in result.findings if f.check_id == "SSRF-001")
        assert finding.matched_value == "10.0.0.1"


# ===========================================================================
# 18. _CHECK_WEIGHTS completeness
# ===========================================================================

class TestCheckWeights:
    def test_all_seven_check_ids_present(self):
        expected = {f"SSRF-00{i}" for i in range(1, 8)}
        assert expected.issubset(set(_CHECK_WEIGHTS.keys()))

    def test_all_weights_positive(self):
        assert all(w > 0 for w in _CHECK_WEIGHTS.values())
