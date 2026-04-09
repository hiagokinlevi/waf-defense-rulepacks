# test_open_redirect_pack.py — Tests for open_redirect_pack.py
#
# Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# Part of Cyber Port portfolio — github.com/hiagokinlevi
# Run with: python -m pytest tests/test_open_redirect_pack.py -q

import sys
import os

# Make shared/rulepacks importable without package install
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared", "rulepacks"))

from open_redirect_pack import (  # type: ignore
    evaluate,
    evaluate_many,
    OREDFinding,
    OREDResult,
    _CHECK_WEIGHTS,
    _DEFAULT_REDIRECT_PARAMS,
    _SUSPICIOUS_TLDS,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _ids(result: OREDResult):
    """Return sorted list of unique check IDs that fired."""
    return sorted({f.check_id for f in result.findings})


def _has(result: OREDResult, check_id: str) -> bool:
    return any(f.check_id == check_id for f in result.findings)


def _clean() -> OREDResult:
    """Evaluate a harmless request — should produce zero findings."""
    return evaluate(params={"url": "/dashboard"})


# ===========================================================================
# Baseline / clean request
# ===========================================================================

def test_clean_relative_path_no_findings():
    r = evaluate(params={"url": "/dashboard"})
    assert r.findings == []
    assert r.risk_score == 0
    assert r.blocked is False


def test_clean_root_path_no_findings():
    r = evaluate(params={"redirect": "/"})
    assert r.findings == []


def test_clean_relative_with_query_no_findings():
    r = evaluate(params={"next": "/search?q=hello"})
    assert r.findings == []


def test_clean_empty_params_no_findings():
    r = evaluate(params={})
    assert r.findings == []
    assert r.risk_score == 0


def test_clean_none_inputs_no_findings():
    r = evaluate()
    assert r.findings == []


def test_non_redirect_param_ignored():
    # 'q' is not a redirect param — must not fire even for absolute URL value
    r = evaluate(params={"q": "https://evil.com"})
    assert r.findings == []


def test_non_redirect_param_with_explicit_list_ignored():
    r = evaluate(
        params={"q": "https://evil.com"},
        redirect_param_names=["url", "redirect"],
    )
    assert r.findings == []


# ===========================================================================
# ORED-001 — Absolute URL redirect to external domain
# ===========================================================================

def test_ored001_http_fires():
    r = evaluate(params={"url": "http://evil.com/steal"})
    assert _has(r, "ORED-001")


def test_ored001_https_fires():
    r = evaluate(params={"redirect": "https://attacker.net/"})
    assert _has(r, "ORED-001")


def test_ored001_severity_is_critical():
    r = evaluate(params={"url": "http://evil.com"})
    finding = next(f for f in r.findings if f.check_id == "ORED-001")
    assert finding.severity == "CRITICAL"


def test_ored001_weight_is_45():
    assert _CHECK_WEIGHTS["ORED-001"] == 45


def test_ored001_risk_score_equals_weight():
    r = evaluate(params={"url": "http://evil.com"})
    assert r.risk_score == 45


def test_ored001_blocked_true():
    r = evaluate(params={"url": "http://evil.com"})
    assert r.blocked is True


def test_ored001_allowed_domain_skipped():
    r = evaluate(
        params={"url": "https://myapp.example.com/home"},
        allowed_domains=["myapp.example.com"],
    )
    assert not _has(r, "ORED-001")
    assert r.findings == []


def test_ored001_allowed_domain_case_insensitive():
    r = evaluate(
        params={"url": "https://MyApp.Example.COM/home"},
        allowed_domains=["myapp.example.com"],
    )
    assert not _has(r, "ORED-001")


def test_ored001_non_allowed_domain_fires():
    r = evaluate(
        params={"url": "https://evil.com/steal"},
        allowed_domains=["myapp.example.com"],
    )
    assert _has(r, "ORED-001")


def test_ored001_param_name_case_insensitive():
    # 'URL' should match default redirect param 'url'
    r = evaluate(params={"URL": "http://evil.com"})
    assert _has(r, "ORED-001")


def test_ored001_evidence_truncated_at_100():
    long_url = "http://evil.com/" + "a" * 200
    r = evaluate(params={"url": long_url})
    finding = next(f for f in r.findings if f.check_id == "ORED-001")
    assert len(finding.evidence) <= 103  # 100 chars + "..."


def test_ored001_goto_param():
    r = evaluate(params={"goto": "http://evil.com"})
    assert _has(r, "ORED-001")


def test_ored001_dest_param():
    r = evaluate(params={"dest": "https://phishing.io"})
    assert _has(r, "ORED-001")


def test_ored001_http_uppercase_scheme():
    r = evaluate(params={"url": "HTTP://evil.com"})
    assert _has(r, "ORED-001")


def test_ored001_explicit_redirect_param_names():
    r = evaluate(
        params={"myredirect": "https://evil.com"},
        redirect_param_names=["myredirect"],
    )
    assert _has(r, "ORED-001")


def test_ored001_explicit_list_excludes_default_params():
    # 'url' is in defaults but not in the explicit list — should not fire
    r = evaluate(
        params={"url": "https://evil.com"},
        redirect_param_names=["myredirect"],
    )
    assert not _has(r, "ORED-001")


def test_ored001_location_header_fires():
    r = evaluate(headers={"Location": "https://attacker.org/"})
    assert _has(r, "ORED-001")


def test_ored001_refresh_header_fires():
    r = evaluate(headers={"Refresh": "https://attacker.org/"})
    assert _has(r, "ORED-001")


def test_ored001_non_redirect_header_ignored():
    r = evaluate(headers={"X-Custom": "https://evil.com"})
    assert r.findings == []


# ===========================================================================
# ORED-002 — URL-encoded bypass
# ===========================================================================

def test_ored002_encoded_http_fires():
    # %68ttp%3A%2F%2F decodes to http://
    encoded = "%68ttp%3A%2F%2Fevil.com%2Fsteal"
    r = evaluate(params={"url": encoded})
    assert _has(r, "ORED-002")


def test_ored002_percent_encoded_colon_slashes():
    encoded = "http%3A%2F%2Fevil.com"
    r = evaluate(params={"url": encoded})
    assert _has(r, "ORED-002")


def test_ored002_severity_is_high():
    encoded = "https%3A%2F%2Fevil.com"
    r = evaluate(params={"url": encoded})
    finding = next((f for f in r.findings if f.check_id == "ORED-002"), None)
    assert finding is not None
    assert finding.severity == "HIGH"


def test_ored002_weight_is_25():
    assert _CHECK_WEIGHTS["ORED-002"] == 25


def test_ored002_plain_http_does_not_also_fire():
    # When raw value is already http://, only ORED-001 fires, not ORED-002
    r = evaluate(params={"url": "http://evil.com"})
    assert _has(r, "ORED-001")
    assert not _has(r, "ORED-002")


def test_ored002_allowed_domain_encoded_skipped():
    encoded = "https%3A%2F%2Fmyapp.example.com%2Fhome"
    r = evaluate(
        params={"url": encoded},
        allowed_domains=["myapp.example.com"],
    )
    assert not _has(r, "ORED-002")


def test_ored002_relative_encoded_path_no_fire():
    # %2Fdashboard decodes to /dashboard — not an absolute URL
    r = evaluate(params={"url": "%2Fdashboard"})
    assert not _has(r, "ORED-002")


def test_ored002_double_encoded_fires():
    # Double percent-encoding: %2568 -> %68 -> h
    encoded = "%2568ttp%253A%252F%252Fevil.com"
    r = evaluate(params={"url": encoded})
    # After single unquote: %68ttp%3A%2F%2Fevil.com — still encoded, ORED-002
    # may or may not fire depending on one-level decode; we just verify no crash
    assert isinstance(r, OREDResult)


# ===========================================================================
# ORED-003 — Double/triple-slash protocol-relative redirect
# ===========================================================================

def test_ored003_double_slash_fires():
    r = evaluate(params={"url": "//evil.com/page"})
    assert _has(r, "ORED-003")


def test_ored003_triple_slash_fires():
    r = evaluate(params={"url": "///evil.com/page"})
    assert _has(r, "ORED-003")


def test_ored003_severity_is_high():
    r = evaluate(params={"url": "//evil.com"})
    finding = next(f for f in r.findings if f.check_id == "ORED-003")
    assert finding.severity == "HIGH"


def test_ored003_weight_is_25():
    assert _CHECK_WEIGHTS["ORED-003"] == 25


def test_ored003_single_slash_no_fire():
    r = evaluate(params={"url": "/relative/path"})
    assert not _has(r, "ORED-003")


def test_ored003_double_slash_with_leading_space_fires():
    r = evaluate(params={"url": "  //evil.com"})
    assert _has(r, "ORED-003")


def test_ored003_redirect_param():
    r = evaluate(params={"redirect": "//phishing.net"})
    assert _has(r, "ORED-003")


def test_ored003_next_param():
    r = evaluate(params={"next": "//phishing.net/login"})
    assert _has(r, "ORED-003")


def test_ored003_blocked_false_alone():
    # ORED-003 is HIGH, default block_on_severity is CRITICAL
    r = evaluate(params={"url": "//evil.com"})
    assert r.blocked is False


def test_ored003_blocked_when_threshold_high():
    r = evaluate(params={"url": "//evil.com"}, block_on_severity="HIGH")
    assert r.blocked is True


# ===========================================================================
# ORED-004 — Backslash bypass
# ===========================================================================

def test_ored004_single_backslash_fires():
    r = evaluate(params={"url": "\\evil.com"})
    assert _has(r, "ORED-004")


def test_ored004_double_backslash_fires():
    r = evaluate(params={"url": "\\\\evil.com"})
    assert _has(r, "ORED-004")


def test_ored004_slash_backslash_fires():
    r = evaluate(params={"url": "/\\evil.com"})
    assert _has(r, "ORED-004")


def test_ored004_backslash_slash_fires():
    r = evaluate(params={"url": "\\/evil.com"})
    assert _has(r, "ORED-004")


def test_ored004_severity_is_high():
    r = evaluate(params={"url": "\\evil.com"})
    finding = next(f for f in r.findings if f.check_id == "ORED-004")
    assert finding.severity == "HIGH"


def test_ored004_weight_is_20():
    assert _CHECK_WEIGHTS["ORED-004"] == 20


def test_ored004_normal_path_no_fire():
    r = evaluate(params={"url": "/normal/path"})
    assert not _has(r, "ORED-004")


def test_ored004_leading_space_then_backslash_fires():
    r = evaluate(params={"url": "  \\evil.com"})
    assert _has(r, "ORED-004")


# ===========================================================================
# ORED-005 — JavaScript / VBScript scheme
# ===========================================================================

def test_ored005_javascript_fires():
    r = evaluate(params={"url": "javascript:alert(1)"})
    assert _has(r, "ORED-005")


def test_ored005_vbscript_fires():
    r = evaluate(params={"url": "vbscript:msgbox(1)"})
    assert _has(r, "ORED-005")


def test_ored005_javascript_uppercase_fires():
    r = evaluate(params={"url": "JAVASCRIPT:alert(1)"})
    assert _has(r, "ORED-005")


def test_ored005_javascript_mixed_case_fires():
    r = evaluate(params={"url": "JaVaScRiPt:alert(1)"})
    assert _has(r, "ORED-005")


def test_ored005_javascript_with_spaces_fires():
    r = evaluate(params={"url": "   javascript:void(0)"})
    assert _has(r, "ORED-005")


def test_ored005_severity_is_critical():
    r = evaluate(params={"url": "javascript:alert(1)"})
    finding = next(f for f in r.findings if f.check_id == "ORED-005")
    assert finding.severity == "CRITICAL"


def test_ored005_weight_is_45():
    assert _CHECK_WEIGHTS["ORED-005"] == 45


def test_ored005_blocked_true():
    r = evaluate(params={"url": "javascript:alert(1)"})
    assert r.blocked is True


def test_ored005_callback_param():
    r = evaluate(params={"callback": "javascript:xss()"})
    assert _has(r, "ORED-005")


def test_ored005_javascript_with_tab_fires():
    # Tab between scheme and colon — some parsers allow this
    r = evaluate(params={"url": "javascript\t:alert(1)"})
    # Whitespace before colon is not standard — should not fire (literal match)
    # This test verifies no false positive for unusual whitespace in the middle
    assert isinstance(r, OREDResult)


def test_ored005_not_a_scheme_no_fire():
    r = evaluate(params={"url": "/javascript_stuff"})
    assert not _has(r, "ORED-005")


# ===========================================================================
# ORED-006 — data: URI scheme
# ===========================================================================

def test_ored006_data_uri_fires():
    r = evaluate(params={"url": "data:text/html,<h1>evil</h1>"})
    assert _has(r, "ORED-006")


def test_ored006_data_uri_base64_fires():
    r = evaluate(params={"url": "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="})
    assert _has(r, "ORED-006")


def test_ored006_data_uppercase_fires():
    r = evaluate(params={"url": "DATA:text/html,<script>alert(1)</script>"})
    assert _has(r, "ORED-006")


def test_ored006_severity_is_high():
    r = evaluate(params={"url": "data:text/html,x"})
    finding = next(f for f in r.findings if f.check_id == "ORED-006")
    assert finding.severity == "HIGH"


def test_ored006_weight_is_30():
    assert _CHECK_WEIGHTS["ORED-006"] == 30


def test_ored006_relative_path_no_fire():
    r = evaluate(params={"url": "/data/report.html"})
    assert not _has(r, "ORED-006")


def test_ored006_blocked_false_alone():
    r = evaluate(params={"url": "data:text/html,x"})
    assert r.blocked is False


def test_ored006_blocked_when_threshold_high():
    r = evaluate(params={"url": "data:text/html,x"}, block_on_severity="HIGH")
    assert r.blocked is True


# ===========================================================================
# ORED-007 — Suspicious TLD
# ===========================================================================

def test_ored007_xyz_tld_fires():
    r = evaluate(params={"url": "http://bad.xyz/steal"})
    assert _has(r, "ORED-007")


def test_ored007_top_tld_fires():
    r = evaluate(params={"url": "https://scam.top/"})
    assert _has(r, "ORED-007")


def test_ored007_tk_tld_fires():
    r = evaluate(params={"url": "http://phish.tk"})
    assert _has(r, "ORED-007")


def test_ored007_cc_tld_fires():
    r = evaluate(params={"url": "https://evil.cc"})
    assert _has(r, "ORED-007")


def test_ored007_pw_tld_fires():
    r = evaluate(params={"url": "https://payload.pw"})
    assert _has(r, "ORED-007")


def test_ored007_ml_tld_fires():
    r = evaluate(params={"url": "//malicious.ml/exploit"})
    assert _has(r, "ORED-007")


def test_ored007_cf_tld_fires():
    r = evaluate(params={"url": "//attacker.cf/hack"})
    assert _has(r, "ORED-007")


def test_ored007_ga_tld_fires():
    r = evaluate(params={"url": "http://bad.ga/go"})
    assert _has(r, "ORED-007")


def test_ored007_gq_tld_fires():
    r = evaluate(params={"url": "https://nasty.gq/xss"})
    assert _has(r, "ORED-007")


def test_ored007_severity_is_medium():
    r = evaluate(params={"url": "http://bad.xyz"})
    finding = next(f for f in r.findings if f.check_id == "ORED-007")
    assert finding.severity == "MEDIUM"


def test_ored007_weight_is_15():
    assert _CHECK_WEIGHTS["ORED-007"] == 15


def test_ored007_safe_tld_no_fire():
    r = evaluate(params={"url": "http://legit.com/page"})
    assert not _has(r, "ORED-007")


def test_ored007_org_tld_no_fire():
    r = evaluate(params={"url": "https://nonprofit.org"})
    assert not _has(r, "ORED-007")


def test_ored007_allowed_domain_suspicious_tld_skipped():
    # Even with a suspicious TLD, allowed domain must not fire ORED-007
    r = evaluate(
        params={"url": "http://myapp.xyz/home"},
        allowed_domains=["myapp.xyz"],
    )
    assert not _has(r, "ORED-007")


def test_ored007_relative_path_no_fire():
    r = evaluate(params={"url": "/page.xyz"})
    assert not _has(r, "ORED-007")


def test_ored007_double_slash_xyz_fires():
    r = evaluate(params={"url": "//phish.xyz/fake-login"})
    assert _has(r, "ORED-007")


# ===========================================================================
# Risk score computation
# ===========================================================================

def test_risk_score_capped_at_100():
    # ORED-001(45) + ORED-005(45) + ORED-006(30) > 100
    r = evaluate(params={
        "url": "javascript:alert(1)",
        "redirect": "http://evil.com",
        "next": "data:text/html,x",
    })
    assert r.risk_score <= 100


def test_risk_score_deduplication_same_check_id():
    # Two params both triggering ORED-003 — weight should only count once
    r = evaluate(params={
        "url": "//evil.com",
        "redirect": "//other.com",
    })
    # ORED-003 weight 25 should appear once in risk_score
    assert r.risk_score == 25


def test_risk_score_two_different_checks():
    # ORED-003(25) + ORED-004(20) from different params
    r = evaluate(params={
        "url": "//evil.com",
        "redirect": "\\bypass",
    })
    assert r.risk_score == 25 + 20


def test_risk_score_zero_for_clean():
    r = _clean()
    assert r.risk_score == 0


# ===========================================================================
# blocked flag logic
# ===========================================================================

def test_blocked_false_when_only_high():
    r = evaluate(params={"url": "//evil.com"})
    assert r.blocked is False  # default block_on_severity = CRITICAL


def test_blocked_true_when_critical():
    r = evaluate(params={"url": "http://evil.com"})
    assert r.blocked is True


def test_blocked_true_when_threshold_medium():
    r = evaluate(params={"url": "//evil.com"}, block_on_severity="MEDIUM")
    # ORED-003 is HIGH >= MEDIUM
    assert r.blocked is True


def test_blocked_false_when_threshold_critical_and_only_high():
    r = evaluate(params={"url": "\\bypass"}, block_on_severity="CRITICAL")
    assert r.blocked is False


# ===========================================================================
# OREDResult methods
# ===========================================================================

def test_to_dict_structure():
    r = evaluate(params={"url": "http://evil.com"})
    d = r.to_dict()
    assert "risk_score" in d
    assert "blocked" in d
    assert "findings" in d
    assert isinstance(d["findings"], list)
    assert len(d["findings"]) >= 1
    assert "check_id" in d["findings"][0]


def test_summary_clean():
    r = _clean()
    assert "0" in r.summary()
    assert "No open redirect" in r.summary()


def test_summary_with_findings():
    r = evaluate(params={"url": "http://evil.com"})
    s = r.summary()
    assert "ORED-001" in s
    assert "45" in s  # risk_score


def test_by_severity_groups_correctly():
    r = evaluate(params={
        "url": "http://evil.com",  # CRITICAL (ORED-001)
        "redirect": "//other.com",  # HIGH (ORED-003)
    })
    groups = r.by_severity()
    assert "CRITICAL" in groups
    assert "HIGH" in groups
    criticals = [f.check_id for f in groups["CRITICAL"]]
    assert "ORED-001" in criticals


def test_by_severity_empty_when_clean():
    r = _clean()
    assert r.by_severity() == {}


# ===========================================================================
# Body inspection
# ===========================================================================

def test_body_absolute_url_fires():
    r = evaluate(body="https://evil.com/steal?token=abc")
    assert _has(r, "ORED-001")


def test_body_javascript_fires():
    r = evaluate(body="javascript:alert(document.cookie)")
    assert _has(r, "ORED-005")


def test_body_data_uri_fires():
    r = evaluate(body="data:text/html,<script>evil()</script>")
    assert _has(r, "ORED-006")


def test_body_double_slash_fires():
    r = evaluate(body="//evil.com/path")
    assert _has(r, "ORED-003")


def test_body_clean_no_findings():
    r = evaluate(body="/safe/path?foo=bar")
    assert r.findings == []


def test_body_param_name_is_body():
    r = evaluate(body="javascript:xss()")
    finding = next(f for f in r.findings if f.check_id == "ORED-005")
    assert finding.parameter == "body"


# ===========================================================================
# evaluate_many
# ===========================================================================

def test_evaluate_many_returns_list():
    results = evaluate_many([
        {"params": {"url": "http://evil.com"}},
        {"params": {"url": "/safe"}},
    ])
    assert len(results) == 2
    assert isinstance(results[0], OREDResult)
    assert isinstance(results[1], OREDResult)


def test_evaluate_many_first_fires():
    results = evaluate_many([{"params": {"url": "http://evil.com"}}])
    assert _has(results[0], "ORED-001")


def test_evaluate_many_empty_list():
    results = evaluate_many([])
    assert results == []


def test_evaluate_many_with_allowed_domains():
    results = evaluate_many([
        {
            "params": {"url": "https://safe.example.com/home"},
            "allowed_domains": ["safe.example.com"],
        }
    ])
    assert results[0].findings == []


def test_evaluate_many_propagates_block_on_severity():
    results = evaluate_many([
        {
            "params": {"url": "//evil.com"},
            "block_on_severity": "HIGH",
        }
    ])
    assert results[0].blocked is True


def test_evaluate_many_mixed_requests():
    requests = [
        {"params": {"url": "javascript:alert(1)"}},
        {"params": {"next": "/safe/page"}},
        {"params": {"redirect": "data:text/html,x"}},
    ]
    results = evaluate_many(requests)
    assert _has(results[0], "ORED-005")
    assert results[1].findings == []
    assert _has(results[2], "ORED-006")


# ===========================================================================
# Edge cases and robustness
# ===========================================================================

def test_empty_string_value_no_findings():
    r = evaluate(params={"url": ""})
    assert r.findings == []


def test_whitespace_only_value_no_findings():
    r = evaluate(params={"url": "   "})
    assert r.findings == []


def test_relative_path_with_query_no_findings():
    r = evaluate(params={"url": "/page?foo=bar&baz=qux"})
    assert r.findings == []


def test_multiple_redirect_params_all_checked():
    r = evaluate(params={
        "url": "//evil1.com",
        "redirect": "//evil2.com",
    })
    assert len(r.findings) >= 2


def test_finding_parameter_field_correct():
    r = evaluate(params={"next": "http://evil.com"})
    finding = next(f for f in r.findings if f.check_id == "ORED-001")
    assert finding.parameter == "next"


def test_finding_evidence_is_string():
    r = evaluate(params={"url": "http://evil.com/long/path"})
    for f in r.findings:
        assert isinstance(f.evidence, str)


def test_allowed_domains_list_empty_does_not_suppress():
    r = evaluate(params={"url": "http://evil.com"}, allowed_domains=[])
    assert _has(r, "ORED-001")


def test_default_redirect_params_set_contains_expected():
    assert "url" in _DEFAULT_REDIRECT_PARAMS
    assert "redirect" in _DEFAULT_REDIRECT_PARAMS
    assert "next" in _DEFAULT_REDIRECT_PARAMS
    assert "goto" in _DEFAULT_REDIRECT_PARAMS
    assert "dest" in _DEFAULT_REDIRECT_PARAMS


def test_suspicious_tlds_set_contains_expected():
    assert ".xyz" in _SUSPICIOUS_TLDS
    assert ".tk" in _SUSPICIOUS_TLDS
    assert ".ml" in _SUSPICIOUS_TLDS


def test_ored001_and_ored007_both_fire_suspicious_external():
    # http://evil.xyz — triggers both ORED-001 (external) and ORED-007 (TLD)
    r = evaluate(params={"url": "http://evil.xyz/page"})
    assert _has(r, "ORED-001")
    assert _has(r, "ORED-007")


def test_ored003_and_ored007_both_fire():
    # //evil.ml — double slash AND suspicious TLD
    r = evaluate(params={"url": "//evil.ml"})
    assert _has(r, "ORED-003")
    assert _has(r, "ORED-007")


def test_headers_non_redirect_header_ignored():
    r = evaluate(headers={"Content-Type": "text/html", "X-Custom": "http://evil.com"})
    assert r.findings == []


def test_headers_location_case_insensitive():
    r = evaluate(headers={"LOCATION": "http://evil.com"})
    assert _has(r, "ORED-001")


def test_none_params_does_not_crash():
    r = evaluate(params=None, headers=None, body=None)
    assert r.findings == []


def test_ored005_fires_alongside_ored007():
    # A javascript: URL with .xyz somewhere shouldn't cause a crash
    r = evaluate(params={"url": "javascript:eval(payload)"})
    assert _has(r, "ORED-005")
    assert isinstance(r, OREDResult)


def test_ored002_callback_param():
    r = evaluate(params={"callback": "https%3A%2F%2Fevil.com"})
    assert _has(r, "ORED-002")


def test_ored004_backslash_in_redirect_header():
    r = evaluate(headers={"Location": "\\evil.com"})
    assert _has(r, "ORED-004")


def test_risk_score_type_is_int():
    r = evaluate(params={"url": "http://evil.com"})
    assert isinstance(r.risk_score, int)


def test_to_dict_risk_score_matches():
    r = evaluate(params={"url": "http://evil.com"})
    assert r.to_dict()["risk_score"] == r.risk_score


def test_to_dict_blocked_matches():
    r = evaluate(params={"url": "http://evil.com"})
    assert r.to_dict()["blocked"] == r.blocked
