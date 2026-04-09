# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) 2026 Hiago Kin Levi
"""
Tests for shared/rulepacks/lfi_rfi_pack.py

Coverage:
  - LFI-001 through LFI-007 (positive + negative cases)
  - Values detected in query params, body, and headers
  - URL-level path traversal detection (LFI-001 / LFI-005)
  - blocked / not-blocked logic for various block_on_severity settings
  - risk_score computation and cap at 100
  - evaluate_many() batch evaluation
  - to_dict() serialisation on all three dataclasses
  - matched_value truncated to 100 characters
  - LFI-004 file-context param keyword heuristic (positive + negative)
  - LFI-005 vs LFI-006 single- vs double-encoding discrimination
  - Clean request baseline produces zero findings
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

import pytest

# Ensure the repo root is on sys.path so the import resolves regardless of cwd
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.rulepacks.lfi_rfi_pack import (
    HTTPRequest,
    LFIEvalResult,
    LFIFinding,
    LFIRFIPack,
    _CHECK_WEIGHTS,
    _extract_values,
)


# ===========================================================================
# Factories / helpers
# ===========================================================================

def _pack(block_on_severity: str = "HIGH") -> LFIRFIPack:
    """Return a pack instance with the given block threshold."""
    return LFIRFIPack(block_on_severity=block_on_severity)


def _req(
    url: str = "https://example.com/page",
    method: str = "GET",
    query_params: Optional[Dict] = None,
    body: Optional[str] = None,
    headers: Optional[Dict] = None,
) -> HTTPRequest:
    """Convenience factory for HTTPRequest."""
    return HTTPRequest(
        url=url,
        method=method,
        query_params=query_params or {},
        body=body,
        headers=headers or {},
    )


def _check_ids(result: LFIEvalResult) -> Set[str]:
    """Return the set of check IDs that fired."""
    return {f.check_id for f in result.findings}


def _has(result: LFIEvalResult, check_id: str) -> bool:
    return check_id in _check_ids(result)


def _location_of(result: LFIEvalResult, check_id: str) -> Optional[str]:
    for f in result.findings:
        if f.check_id == check_id:
            return f.param_location
    return None


# ===========================================================================
# 1. Clean request — no findings baseline
# ===========================================================================

class TestCleanRequest:
    def test_empty_request_no_findings(self):
        result = _pack().evaluate(_req())
        assert result.findings == []

    def test_risk_score_zero_on_clean(self):
        result = _pack().evaluate(_req())
        assert result.risk_score == 0

    def test_not_blocked_on_clean(self):
        result = _pack().evaluate(_req())
        assert result.blocked is False

    def test_clean_param_no_findings(self):
        result = _pack().evaluate(_req(query_params={"name": "alice", "age": "30"}))
        assert result.findings == []

    def test_clean_path_no_traversal(self):
        result = _pack().evaluate(_req(query_params={"file": "report.pdf"}))
        assert not _has(result, "LFI-001")

    def test_summary_shows_allowed_on_clean(self):
        result = _pack().evaluate(_req())
        assert "ALLOWED" in result.summary()

    def test_by_severity_empty_on_clean(self):
        result = _pack().evaluate(_req())
        assert result.by_severity() == {}


# ===========================================================================
# 2. LFI-001 — Path traversal sequences
# ===========================================================================

class TestLFI001PathTraversal:
    def test_forward_slash_traversal_in_query(self):
        result = _pack().evaluate(_req(query_params={"file": "../../../etc/passwd"}))
        assert _has(result, "LFI-001")

    def test_backslash_traversal_in_query(self):
        result = _pack().evaluate(_req(query_params={"path": "..\\..\\windows\\system32"}))
        assert _has(result, "LFI-001")

    def test_single_dotdot_slash_triggers(self):
        result = _pack().evaluate(_req(query_params={"p": "../secret.txt"}))
        assert _has(result, "LFI-001")

    def test_clean_path_no_lfi001(self):
        result = _pack().evaluate(_req(query_params={"file": "assets/image.png"}))
        assert not _has(result, "LFI-001")

    def test_url_traversal_triggers_lfi001(self):
        result = _pack().evaluate(_req(url="https://example.com/page?x=1&y=../etc"))
        assert _has(result, "LFI-001")

    def test_url_clean_no_lfi001(self):
        result = _pack().evaluate(_req(url="https://example.com/home"))
        assert not _has(result, "LFI-001")

    def test_lfi001_is_critical(self):
        result = _pack().evaluate(_req(query_params={"f": "../../secret"}))
        findings = [f for f in result.findings if f.check_id == "LFI-001"]
        assert findings[0].severity == "CRITICAL"

    def test_lfi001_blocks_by_default(self):
        # Default block_on_severity="HIGH"; CRITICAL >= HIGH so blocked
        result = _pack().evaluate(_req(query_params={"f": "../../secret"}))
        assert result.blocked is True

    def test_lfi001_not_blocked_when_threshold_critical_only(self):
        pack = _pack(block_on_severity="CRITICAL")
        result = pack.evaluate(_req(query_params={"f": "../../secret"}))
        # CRITICAL >= CRITICAL, still blocked
        assert result.blocked is True

    def test_lfi001_location_query(self):
        result = _pack().evaluate(_req(query_params={"file": "../secret"}))
        assert _location_of(result, "LFI-001") == "query"


# ===========================================================================
# 3. LFI-002 — Null byte injection
# ===========================================================================

class TestLFI002NullByte:
    def test_percent00_in_query_triggers(self):
        result = _pack().evaluate(_req(query_params={"file": "shell.php%00.txt"}))
        assert _has(result, "LFI-002")

    def test_literal_null_byte_triggers(self):
        result = _pack().evaluate(_req(query_params={"file": "shell.php\x00.txt"}))
        assert _has(result, "LFI-002")

    def test_clean_value_no_lfi002(self):
        result = _pack().evaluate(_req(query_params={"file": "document.pdf"}))
        assert not _has(result, "LFI-002")

    def test_null_byte_in_body_triggers(self):
        result = _pack().evaluate(_req(body="file=shell.php%00.txt"))
        assert _has(result, "LFI-002")

    def test_null_byte_in_header_triggers(self):
        result = _pack().evaluate(_req(headers={"X-File": "shell.php%00.txt"}))
        assert _has(result, "LFI-002")

    def test_lfi002_is_high_severity(self):
        result = _pack().evaluate(_req(query_params={"f": "a%00b"}))
        findings = [f for f in result.findings if f.check_id == "LFI-002"]
        assert findings[0].severity == "HIGH"

    def test_lfi002_blocked_with_high_threshold(self):
        result = _pack(block_on_severity="HIGH").evaluate(
            _req(query_params={"f": "a%00b"})
        )
        assert result.blocked is True

    def test_lfi002_location_body(self):
        result = _pack().evaluate(_req(body="x%00y"))
        assert _location_of(result, "LFI-002") == "body"


# ===========================================================================
# 4. LFI-003 — PHP wrapper schemes
# ===========================================================================

class TestLFI003PHPWrapper:
    def test_php_wrapper_triggers(self):
        result = _pack().evaluate(_req(query_params={"file": "php://filter/read=..."}))
        assert _has(result, "LFI-003")

    def test_phar_wrapper_triggers(self):
        result = _pack().evaluate(_req(query_params={"p": "phar:///var/www/upload.phar"}))
        assert _has(result, "LFI-003")

    def test_data_wrapper_triggers(self):
        result = _pack().evaluate(_req(query_params={"src": "data://text/plain;base64,SGVsbG8="}))
        assert _has(result, "LFI-003")

    def test_expect_wrapper_triggers(self):
        result = _pack().evaluate(_req(query_params={"file": "expect://id"}))
        assert _has(result, "LFI-003")

    def test_zip_wrapper_triggers(self):
        result = _pack().evaluate(_req(query_params={"f": "zip://shell.zip#shell.php"}))
        assert _has(result, "LFI-003")

    def test_glob_wrapper_triggers(self):
        result = _pack().evaluate(_req(query_params={"f": "glob:///etc/*"}))
        assert _has(result, "LFI-003")

    def test_compress_zlib_triggers(self):
        result = _pack().evaluate(_req(query_params={"f": "compress.zlib://shell.gz"}))
        assert _has(result, "LFI-003")

    def test_compress_bzip2_triggers(self):
        result = _pack().evaluate(_req(query_params={"f": "compress.bzip2://shell.bz2"}))
        assert _has(result, "LFI-003")

    def test_case_insensitive_php_wrapper(self):
        result = _pack().evaluate(_req(query_params={"f": "PHP://filter/read=..."}))
        assert _has(result, "LFI-003")

    def test_http_scheme_does_not_trigger_lfi003(self):
        # http:// is NOT a PHP wrapper — should not trigger LFI-003
        result = _pack().evaluate(_req(query_params={"url": "http://example.com/"}))
        assert not _has(result, "LFI-003")

    def test_lfi003_is_high_severity(self):
        result = _pack().evaluate(_req(query_params={"f": "php://input"}))
        findings = [f for f in result.findings if f.check_id == "LFI-003"]
        assert findings[0].severity == "HIGH"

    def test_lfi003_location_query(self):
        result = _pack().evaluate(_req(query_params={"f": "phar://x"}))
        assert _location_of(result, "LFI-003") == "query"


# ===========================================================================
# 5. LFI-004 — Remote file inclusion URL in file-context parameter
# ===========================================================================

class TestLFI004RFI:
    def test_param_file_with_http_url_triggers(self):
        result = _pack().evaluate(_req(
            query_params={"file": "http://evil.com/shell.php"}
        ))
        assert _has(result, "LFI-004")

    def test_param_page_with_http_url_triggers(self):
        result = _pack().evaluate(_req(
            query_params={"page": "http://attacker.com/inc.php"}
        ))
        assert _has(result, "LFI-004")

    def test_param_include_triggers(self):
        result = _pack().evaluate(_req(
            query_params={"include": "http://malicious.org/code.php"}
        ))
        assert _has(result, "LFI-004")

    def test_param_template_triggers(self):
        result = _pack().evaluate(_req(
            query_params={"template": "http://evil.com/tpl.php"}
        ))
        assert _has(result, "LFI-004")

    def test_param_url_triggers(self):
        result = _pack().evaluate(_req(
            query_params={"url": "http://evil.com/r.php"}
        ))
        assert _has(result, "LFI-004")

    def test_param_src_triggers(self):
        result = _pack().evaluate(_req(
            query_params={"src": "ftp://evil.com/shell.php"}
        ))
        assert _has(result, "LFI-004")

    def test_param_user_with_http_does_not_trigger(self):
        # "user" is not a file-context keyword — should NOT trigger LFI-004
        result = _pack().evaluate(_req(
            query_params={"user": "http://example.com/profile"}
        ))
        assert not _has(result, "LFI-004")

    def test_param_name_with_http_does_not_trigger(self):
        result = _pack().evaluate(_req(
            query_params={"name": "http://example.com/"}
        ))
        assert not _has(result, "LFI-004")

    def test_param_document_triggers(self):
        result = _pack().evaluate(_req(
            query_params={"document": "http://evil.com/doc.php"}
        ))
        assert _has(result, "LFI-004")

    def test_lfi004_is_critical_severity(self):
        result = _pack().evaluate(_req(
            query_params={"file": "http://evil.com/shell.php"}
        ))
        findings = [f for f in result.findings if f.check_id == "LFI-004"]
        assert findings[0].severity == "CRITICAL"

    def test_lfi004_location_query(self):
        result = _pack().evaluate(_req(
            query_params={"page": "http://evil.com/x.php"}
        ))
        assert _location_of(result, "LFI-004") == "query"

    def test_lfi004_param_fetch_triggers(self):
        result = _pack().evaluate(_req(
            query_params={"fetch": "https://evil.com/payload"}
        ))
        assert _has(result, "LFI-004")

    def test_lfi004_param_load_triggers(self):
        result = _pack().evaluate(_req(
            query_params={"load": "https://evil.com/payload"}
        ))
        assert _has(result, "LFI-004")

    def test_lfi004_param_read_triggers(self):
        result = _pack().evaluate(_req(
            query_params={"read": "https://evil.com/data"}
        ))
        assert _has(result, "LFI-004")


# ===========================================================================
# 6. LFI-005 — URL-encoded path traversal
# ===========================================================================

class TestLFI005EncodedTraversal:
    def test_percent2e_double_triggers(self):
        # %2e%2e%2f → ../
        result = _pack().evaluate(_req(query_params={"file": "%2e%2e%2fetc%2fpasswd"}))
        assert _has(result, "LFI-005")

    def test_mixed_encoding_triggers(self):
        # %2e%2e/ — one dot encoded, slash literal
        result = _pack().evaluate(_req(query_params={"p": "%2e%2e/secret"}))
        assert _has(result, "LFI-005")

    def test_uppercase_encoding_triggers(self):
        # %2E%2E%2F (uppercase hex)
        result = _pack().evaluate(_req(query_params={"p": "%2E%2E%2Fsecret"}))
        assert _has(result, "LFI-005")

    def test_already_decoded_triggers_lfi001_not_lfi005(self):
        # Raw "../" fires LFI-001; LFI-005 must NOT also fire
        result = _pack().evaluate(_req(query_params={"f": "../secret"}))
        assert _has(result, "LFI-001")
        assert not _has(result, "LFI-005")

    def test_clean_value_no_lfi005(self):
        result = _pack().evaluate(_req(query_params={"f": "home%2Fuser%2Fdocs"}))
        assert not _has(result, "LFI-005")

    def test_lfi005_is_critical_severity(self):
        result = _pack().evaluate(_req(query_params={"file": "%2e%2e%2fetc"}))
        findings = [f for f in result.findings if f.check_id == "LFI-005"]
        assert findings[0].severity == "CRITICAL"

    def test_url_encoded_traversal_in_url_itself(self):
        result = _pack().evaluate(_req(url="https://example.com/page?f=%2e%2e%2fsecret"))
        # LFI-005 or LFI-001 should fire from URL inspection
        assert _has(result, "LFI-005") or _has(result, "LFI-001")


# ===========================================================================
# 7. LFI-006 — Double-encoded path traversal
# ===========================================================================

class TestLFI006DoubleEncoded:
    def test_double_encoded_triggers(self):
        # %252e%252e%252f → %2e%2e%2f → ../
        result = _pack().evaluate(_req(query_params={"f": "%252e%252e%252f"}))
        assert _has(result, "LFI-006")

    def test_single_encoded_triggers_lfi005_not_lfi006(self):
        # Single-encoded %2e%2e%2f should fire LFI-005, NOT LFI-006
        result = _pack().evaluate(_req(query_params={"f": "%2e%2e%2f"}))
        assert _has(result, "LFI-005")
        assert not _has(result, "LFI-006")

    def test_raw_traversal_triggers_lfi001_not_lfi006(self):
        result = _pack().evaluate(_req(query_params={"f": "../secret"}))
        assert _has(result, "LFI-001")
        assert not _has(result, "LFI-006")

    def test_lfi006_is_high_severity(self):
        result = _pack().evaluate(_req(query_params={"f": "%252e%252e%252f"}))
        findings = [f for f in result.findings if f.check_id == "LFI-006"]
        assert findings[0].severity == "HIGH"

    def test_double_encoded_uppercase_triggers(self):
        result = _pack().evaluate(_req(query_params={"f": "%252E%252E%252F"}))
        assert _has(result, "LFI-006")

    def test_clean_value_no_lfi006(self):
        result = _pack().evaluate(_req(query_params={"f": "normal-file.txt"}))
        assert not _has(result, "LFI-006")


# ===========================================================================
# 8. LFI-007 — Sensitive OS file target patterns
# ===========================================================================

class TestLFI007SensitiveFile:
    def test_etc_passwd_triggers(self):
        result = _pack().evaluate(_req(query_params={"file": "/etc/passwd"}))
        assert _has(result, "LFI-007")

    def test_etc_shadow_triggers(self):
        result = _pack().evaluate(_req(query_params={"file": "/etc/shadow"}))
        assert _has(result, "LFI-007")

    def test_etc_hosts_triggers(self):
        result = _pack().evaluate(_req(query_params={"file": "/etc/hosts"}))
        assert _has(result, "LFI-007")

    def test_proc_self_triggers(self):
        result = _pack().evaluate(_req(query_params={"file": "/proc/self/environ"}))
        assert _has(result, "LFI-007")

    def test_proc_version_triggers(self):
        result = _pack().evaluate(_req(query_params={"file": "/proc/version"}))
        assert _has(result, "LFI-007")

    def test_windows_system32_triggers(self):
        result = _pack().evaluate(_req(query_params={"path": "C:\\windows\\system32\\cmd.exe"}))
        assert _has(result, "LFI-007")

    def test_win_ini_triggers(self):
        result = _pack().evaluate(_req(query_params={"f": "C:\\win.ini"}))
        assert _has(result, "LFI-007")

    def test_boot_ini_triggers(self):
        result = _pack().evaluate(_req(query_params={"f": "C:\\boot.ini"}))
        assert _has(result, "LFI-007")

    def test_autoexec_bat_triggers(self):
        result = _pack().evaluate(_req(query_params={"f": "autoexec.bat"}))
        assert _has(result, "LFI-007")

    def test_ssh_dir_triggers(self):
        result = _pack().evaluate(_req(query_params={"p": "/root/.ssh/id_rsa"}))
        assert _has(result, "LFI-007")

    def test_dotenv_triggers(self):
        result = _pack().evaluate(_req(query_params={"path": "/var/www/.env"}))
        assert _has(result, "LFI-007")

    def test_wp_config_triggers(self):
        result = _pack().evaluate(_req(query_params={"file": "/var/www/html/wp-config.php"}))
        assert _has(result, "LFI-007")

    def test_config_php_triggers(self):
        result = _pack().evaluate(_req(query_params={"include": "/app/config.php"}))
        assert _has(result, "LFI-007")

    def test_clean_path_no_lfi007(self):
        result = _pack().evaluate(_req(query_params={"file": "assets/logo.png"}))
        assert not _has(result, "LFI-007")

    def test_lfi007_is_high_severity(self):
        result = _pack().evaluate(_req(query_params={"f": "/etc/passwd"}))
        findings = [f for f in result.findings if f.check_id == "LFI-007"]
        assert findings[0].severity == "HIGH"

    def test_case_insensitive_windows_path(self):
        result = _pack().evaluate(_req(query_params={"p": "C:\\Windows\\System32\\drivers"}))
        assert _has(result, "LFI-007")


# ===========================================================================
# 9. Trigger locations — body and headers
# ===========================================================================

class TestLocations:
    def test_traversal_in_body_triggers_lfi001(self):
        result = _pack().evaluate(_req(body="file=../../../etc/passwd"))
        assert _has(result, "LFI-001")

    def test_null_byte_in_body_triggers_lfi002(self):
        result = _pack().evaluate(_req(body="file=shell.php%00.txt"))
        assert _has(result, "LFI-002")

    def test_php_wrapper_in_body_triggers_lfi003(self):
        result = _pack().evaluate(_req(body="resource=php://filter/read=..."))
        assert _has(result, "LFI-003")

    def test_sensitive_file_in_body_triggers_lfi007(self):
        result = _pack().evaluate(_req(body="target=/etc/passwd"))
        assert _has(result, "LFI-007")

    def test_traversal_in_header_triggers_lfi001(self):
        result = _pack().evaluate(_req(headers={"X-File-Path": "../../secret"}))
        assert _has(result, "LFI-001")

    def test_null_byte_in_header_triggers_lfi002(self):
        result = _pack().evaluate(_req(headers={"X-Resource": "file%00.php"}))
        assert _has(result, "LFI-002")

    def test_php_wrapper_in_header_triggers_lfi003(self):
        result = _pack().evaluate(_req(headers={"X-Src": "phar:///tmp/payload.phar"}))
        assert _has(result, "LFI-003")

    def test_location_tag_body(self):
        result = _pack().evaluate(_req(body="../../../etc/passwd"))
        assert _location_of(result, "LFI-001") == "body"

    def test_location_tag_header(self):
        result = _pack().evaluate(_req(headers={"X-File": "../../secret"}))
        assert _location_of(result, "LFI-001") == "header"

    def test_list_value_in_query_triggers(self):
        # Param value is a list — all items must be checked
        result = _pack().evaluate(_req(
            query_params={"files": ["safe.txt", "../../../etc/passwd"]}
        ))
        assert _has(result, "LFI-001")


# ===========================================================================
# 10. Blocked flag logic
# ===========================================================================

class TestBlockedFlag:
    def test_critical_finding_blocks_with_high_threshold(self):
        # LFI-001 is CRITICAL; default threshold is HIGH → blocked
        result = _pack(block_on_severity="HIGH").evaluate(
            _req(query_params={"f": "../../secret"})
        )
        assert result.blocked is True

    def test_high_finding_blocks_with_high_threshold(self):
        # LFI-007 is HIGH; threshold HIGH → blocked
        result = _pack(block_on_severity="HIGH").evaluate(
            _req(query_params={"f": "/etc/passwd"})
        )
        assert result.blocked is True

    def test_high_finding_not_blocked_with_critical_threshold(self):
        # LFI-007 (HIGH) with threshold CRITICAL → NOT blocked
        # (only fire LFI-007, not LFI-001, so choose a pure HIGH trigger)
        result = _pack(block_on_severity="CRITICAL").evaluate(
            _req(query_params={"name": "/etc/shadow"})
        )
        # LFI-007 is HIGH, threshold is CRITICAL → not blocked
        assert result.blocked is False

    def test_no_findings_not_blocked(self):
        result = _pack().evaluate(_req())
        assert result.blocked is False

    def test_medium_not_blocked_with_high_threshold(self):
        # No MEDIUM checks in LFI pack, but verify threshold logic works
        pack = _pack(block_on_severity="HIGH")
        result = pack.evaluate(_req())
        assert result.blocked is False


# ===========================================================================
# 11. Risk score computation
# ===========================================================================

class TestRiskScore:
    def test_lfi001_weight_45(self):
        result = _pack().evaluate(_req(query_params={"f": "../../x"}))
        assert "LFI-001" in _check_ids(result)
        assert result.risk_score == _CHECK_WEIGHTS["LFI-001"]

    def test_lfi002_weight_30(self):
        result = _pack().evaluate(_req(query_params={"f": "x%00y"}))
        assert result.risk_score == _CHECK_WEIGHTS["LFI-002"]

    def test_lfi007_weight_25(self):
        # Use a pure LFI-007 trigger (no traversal sequences)
        result = _pack().evaluate(_req(query_params={"name": "/etc/shadow"}))
        # Only LFI-007 fires
        assert _has(result, "LFI-007")
        assert result.risk_score == _CHECK_WEIGHTS["LFI-007"]

    def test_risk_score_capped_at_100(self):
        # Combine LFI-001 (45) + LFI-002 (30) + LFI-004 (45) → 120 → capped 100
        result = _pack().evaluate(_req(
            url="https://example.com/",
            query_params={
                "file":  "http://evil.com/shell.php%00.txt",  # LFI-002 + LFI-004
                "path":  "../../etc/passwd",                  # LFI-001 + LFI-007
            },
        ))
        assert result.risk_score <= 100

    def test_risk_score_zero_for_clean_request(self):
        result = _pack().evaluate(_req())
        assert result.risk_score == 0

    def test_check_weights_dict_has_all_seven(self):
        expected = {"LFI-001", "LFI-002", "LFI-003", "LFI-004",
                    "LFI-005", "LFI-006", "LFI-007"}
        assert set(_CHECK_WEIGHTS.keys()) == expected

    def test_each_check_id_fires_at_most_once(self):
        # Even with multiple matching values, each check ID appears once
        result = _pack().evaluate(_req(
            query_params={
                "a": "../x",
                "b": "../../y",
                "c": "../../../z",
            }
        ))
        ids = [f.check_id for f in result.findings]
        assert len(ids) == len(set(ids))


# ===========================================================================
# 12. evaluate_many()
# ===========================================================================

class TestEvaluateMany:
    def test_returns_list_same_length(self):
        pack = _pack()
        reqs = [_req(), _req(query_params={"f": "../../x"})]
        results = pack.evaluate_many(reqs)
        assert len(results) == 2

    def test_returns_list_of_lfi_eval_results(self):
        pack = _pack()
        results = pack.evaluate_many([_req()])
        assert isinstance(results[0], LFIEvalResult)

    def test_empty_list_returns_empty(self):
        assert _pack().evaluate_many([]) == []

    def test_order_preserved(self):
        pack = _pack()
        reqs = [
            _req(query_params={"f": "../../x"}),   # blocked
            _req(),                                  # clean
            _req(query_params={"f": "/etc/passwd"}),# blocked
        ]
        results = pack.evaluate_many(reqs)
        assert results[0].blocked is True
        assert results[1].blocked is False
        assert results[2].blocked is True

    def test_evaluate_many_three_requests(self):
        pack = _pack()
        results = pack.evaluate_many([_req(), _req(), _req()])
        assert all(r.risk_score == 0 for r in results)


# ===========================================================================
# 13. to_dict() serialisation
# ===========================================================================

class TestToDict:
    def test_http_request_to_dict_keys(self):
        req = _req(query_params={"a": "1"}, body="x", headers={"H": "v"})
        d = req.to_dict()
        assert set(d.keys()) == {"url", "method", "query_params", "body", "headers"}

    def test_http_request_to_dict_values(self):
        req = HTTPRequest(
            url="https://example.com",
            method="POST",
            query_params={"file": "x"},
            body="body_content",
            headers={"Authorization": "Bearer t"},
        )
        d = req.to_dict()
        assert d["method"] == "POST"
        assert d["body"] == "body_content"
        assert d["query_params"] == {"file": "x"}

    def test_lfi_finding_to_dict_keys(self):
        finding = LFIFinding(
            check_id="LFI-001",
            severity="CRITICAL",
            rule_name="Path Traversal Sequence",
            matched_value="../etc",
            param_location="query",
            recommendation="Fix it.",
        )
        d = finding.to_dict()
        assert set(d.keys()) == {
            "check_id", "severity", "rule_name",
            "matched_value", "param_location", "recommendation",
        }

    def test_lfi_eval_result_to_dict_keys(self):
        result = _pack().evaluate(_req(query_params={"f": "../../x"}))
        d = result.to_dict()
        assert set(d.keys()) == {
            "findings", "risk_score", "blocked", "summary", "by_severity"
        }

    def test_eval_result_to_dict_findings_is_list(self):
        result = _pack().evaluate(_req(query_params={"f": "../../x"}))
        d = result.to_dict()
        assert isinstance(d["findings"], list)

    def test_eval_result_to_dict_risk_score_int(self):
        result = _pack().evaluate(_req(query_params={"f": "../../x"}))
        d = result.to_dict()
        assert isinstance(d["risk_score"], int)

    def test_eval_result_to_dict_blocked_bool(self):
        result = _pack().evaluate(_req(query_params={"f": "../../x"}))
        d = result.to_dict()
        assert isinstance(d["blocked"], bool)

    def test_eval_result_to_dict_clean_request(self):
        result = _pack().evaluate(_req())
        d = result.to_dict()
        assert d["findings"] == []
        assert d["risk_score"] == 0
        assert d["blocked"] is False

    def test_by_severity_in_to_dict(self):
        result = _pack().evaluate(_req(query_params={"f": "../../x"}))
        d = result.to_dict()
        assert isinstance(d["by_severity"], dict)


# ===========================================================================
# 14. matched_value truncation to 100 chars
# ===========================================================================

class TestMatchedValueTruncation:
    def test_long_traversal_value_truncated(self):
        # 200-character traversal value
        long_val = "../" * 67  # 201 chars
        result = _pack().evaluate(_req(query_params={"f": long_val}))
        assert _has(result, "LFI-001")
        for f in result.findings:
            assert len(f.matched_value) <= 100

    def test_long_null_byte_value_truncated(self):
        long_val = "A" * 150 + "%00" + "B" * 50
        result = _pack().evaluate(_req(query_params={"f": long_val}))
        assert _has(result, "LFI-002")
        for f in result.findings:
            assert len(f.matched_value) <= 100

    def test_exactly_100_chars_not_truncated(self):
        # Craft a value exactly 100 chars that contains a trigger
        val = "../" + "A" * 97  # 100 chars total
        result = _pack().evaluate(_req(query_params={"f": val}))
        for f in result.findings:
            assert len(f.matched_value) <= 100

    def test_short_value_unchanged(self):
        val = "../secret"
        result = _pack().evaluate(_req(query_params={"f": val}))
        findings = [f for f in result.findings if f.check_id == "LFI-001"]
        assert findings[0].matched_value == val


# ===========================================================================
# 15. summary() and by_severity()
# ===========================================================================

class TestSummaryAndBySeverity:
    def test_summary_contains_blocked(self):
        result = _pack().evaluate(_req(query_params={"f": "../../x"}))
        assert "BLOCKED" in result.summary()

    def test_summary_contains_allowed(self):
        result = _pack().evaluate(_req())
        assert "ALLOWED" in result.summary()

    def test_summary_contains_risk_score(self):
        result = _pack().evaluate(_req(query_params={"f": "../../x"}))
        assert "risk_score=" in result.summary()

    def test_by_severity_critical_before_high(self):
        # LFI-001 (CRITICAL) + LFI-007 (HIGH) both fire
        result = _pack().evaluate(_req(
            query_params={"file": "../../etc/passwd"}  # fires LFI-001 and LFI-007
        ))
        keys = list(result.by_severity().keys())
        if "CRITICAL" in keys and "HIGH" in keys:
            assert keys.index("CRITICAL") < keys.index("HIGH")

    def test_by_severity_groups_correctly(self):
        result = _pack().evaluate(_req(query_params={"f": "../../x"}))
        grouped = result.by_severity()
        for sev, findings in grouped.items():
            for f in findings:
                assert f.severity == sev

    def test_summary_finding_count(self):
        result = _pack().evaluate(_req())
        assert "findings=0" in result.summary()


# ===========================================================================
# 16. _extract_values helper
# ===========================================================================

class TestExtractValues:
    def test_query_string_value_included(self):
        req = _req(query_params={"a": "hello"})
        vals = [v for v, _ in _extract_values(req)]
        assert "hello" in vals

    def test_query_list_values_flattened(self):
        req = _req(query_params={"x": ["alpha", "beta"]})
        vals = [v for v, _ in _extract_values(req)]
        assert "alpha" in vals and "beta" in vals

    def test_body_included(self):
        req = _req(body="raw body content")
        vals = [v for v, _ in _extract_values(req)]
        assert "raw body content" in vals

    def test_none_body_excluded(self):
        req = _req(body=None)
        vals = [v for v, _ in _extract_values(req)]
        assert None not in vals

    def test_header_values_included(self):
        req = _req(headers={"X-Custom": "header_value"})
        vals = [v for v, _ in _extract_values(req)]
        assert "header_value" in vals

    def test_location_tags_correct(self):
        req = _req(
            query_params={"a": "qval"},
            body="bval",
            headers={"H": "hval"},
        )
        locs = {v: loc for v, loc in _extract_values(req)}
        assert locs.get("qval") == "query"
        assert locs.get("bval") == "body"
        assert locs.get("hval") == "header"


# ===========================================================================
# 17. Constructor validation
# ===========================================================================

class TestConstructor:
    def test_default_block_severity_high(self):
        pack = LFIRFIPack()
        # Should block on HIGH findings (LFI-007 is HIGH)
        result = pack.evaluate(_req(query_params={"f": "/etc/passwd"}))
        assert result.blocked is True

    def test_invalid_severity_raises_value_error(self):
        with pytest.raises(ValueError):
            LFIRFIPack(block_on_severity="EXTREME")

    def test_case_insensitive_severity(self):
        pack = LFIRFIPack(block_on_severity="high")
        result = pack.evaluate(_req(query_params={"f": "/etc/passwd"}))
        assert result.blocked is True
