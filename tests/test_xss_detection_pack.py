# test_xss_detection_pack.py — Cyber Port WAF Rulepack Tests
#
# Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# pytest-compatible test suite for xss_detection_pack.py
# Run with: python -m pytest tests/test_xss_detection_pack.py -q

import sys
import os

# Ensure the shared/rulepacks package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared", "rulepacks"))

from xss_detection_pack import (
    XSSFinding,
    XSSResult,
    evaluate,
    evaluate_many,
    _CHECK_WEIGHTS,
)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _check_ids(result: XSSResult):
    """Return the set of check_ids that fired."""
    return {f.check_id for f in result.findings}


def _has_check(result: XSSResult, check_id: str) -> bool:
    return check_id in _check_ids(result)


def _clean(result: XSSResult) -> bool:
    return len(result.findings) == 0


# ===========================================================================
# CLEAN / SAFE INPUT TESTS
# ===========================================================================

def test_clean_no_input():
    """No params, headers, or body — expect clean result."""
    result = evaluate()
    assert _clean(result)
    assert result.risk_score == 0
    assert result.blocked is False


def test_clean_empty_params():
    result = evaluate(params={})
    assert _clean(result)


def test_clean_empty_headers():
    result = evaluate(headers={})
    assert _clean(result)


def test_clean_empty_body():
    result = evaluate(body="")
    assert _clean(result)


def test_clean_plain_text_param():
    result = evaluate(params={"name": "Alice"})
    assert _clean(result)


def test_clean_html_paragraph():
    """Safe, passive HTML should not trigger XSS rules."""
    result = evaluate(params={"content": "<p>Hello world</p>"})
    assert _clean(result)


def test_clean_html_anchor():
    """An anchor tag with a safe href should not trigger XSS rules."""
    result = evaluate(params={"link": '<a href="https://example.com">Click</a>'})
    assert _clean(result)


def test_clean_normal_url():
    result = evaluate(params={"redirect": "https://example.com/page?foo=bar"})
    assert _clean(result)


def test_clean_json_body():
    result = evaluate(body='{"user": "bob", "age": 30}')
    assert _clean(result)


def test_clean_sql_like_string():
    """SQL injection strings should not trigger XSS detections."""
    result = evaluate(params={"q": "' OR 1=1 --"})
    assert _clean(result)


def test_clean_email_param():
    result = evaluate(params={"email": "user@example.com"})
    assert _clean(result)


def test_clean_numeric_body():
    result = evaluate(body="42")
    assert _clean(result)


def test_clean_html_comment():
    """HTML comment without script content should be clean."""
    result = evaluate(params={"desc": "<!-- this is a comment -->"})
    assert _clean(result)


def test_clean_input_tag():
    """An <input> tag does not match any XSS-005 vectors."""
    result = evaluate(params={"html": '<input type="text" value="hello">'})
    assert _clean(result)


def test_clean_div_tag():
    result = evaluate(params={"html": "<div class='container'>content</div>"})
    assert _clean(result)


# ===========================================================================
# XSS-001: REFLECTED XSS
# ===========================================================================

def test_001_script_tag_basic():
    result = evaluate(params={"q": "<script>alert(1)</script>"})
    assert _has_check(result, "XSS-001")
    assert result.risk_score >= _CHECK_WEIGHTS["XSS-001"]
    assert result.blocked is True


def test_001_script_tag_uppercase():
    result = evaluate(params={"q": "<SCRIPT>alert(1)</SCRIPT>"})
    assert _has_check(result, "XSS-001")


def test_001_script_tag_mixed_case():
    result = evaluate(params={"q": "<ScRiPt>alert('xss')"})
    assert _has_check(result, "XSS-001")


def test_001_javascript_scheme():
    result = evaluate(params={"url": "javascript:alert(document.cookie)"})
    assert _has_check(result, "XSS-001")
    assert result.blocked is True


def test_001_javascript_scheme_uppercase():
    result = evaluate(params={"url": "JAVASCRIPT:alert(1)"})
    assert _has_check(result, "XSS-001")


def test_001_javascript_scheme_with_spaces():
    """Spaces between javascript and colon should still trigger."""
    result = evaluate(params={"href": "javascript  :  alert(1)"})
    assert _has_check(result, "XSS-001")


def test_001_vbscript_scheme():
    result = evaluate(params={"url": "vbscript:MsgBox('XSS')"})
    assert _has_check(result, "XSS-001")
    assert result.blocked is True


def test_001_vbscript_uppercase():
    result = evaluate(params={"url": "VBSCRIPT:MsgBox('XSS')"})
    assert _has_check(result, "XSS-001")


def test_001_data_text_html():
    result = evaluate(params={"src": "data:text/html,<script>alert(1)</script>"})
    assert _has_check(result, "XSS-001")
    assert result.blocked is True


def test_001_data_text_html_base64():
    result = evaluate(params={"src": "data:text/html;base64,PHNjcmlwdD4="})
    assert _has_check(result, "XSS-001")


def test_001_data_application_javascript():
    result = evaluate(params={"src": "data:application/javascript,alert(1)"})
    assert _has_check(result, "XSS-001")


def test_001_data_application_javascript_uppercase():
    result = evaluate(params={"src": "DATA:APPLICATION/JAVASCRIPT,alert(1)"})
    assert _has_check(result, "XSS-001")


def test_001_in_header():
    result = evaluate(headers={"Referer": "javascript:alert(1)"})
    assert _has_check(result, "XSS-001")


def test_001_in_body():
    result = evaluate(body="<script src='evil.js'></script>")
    assert _has_check(result, "XSS-001")


def test_001_script_tag_with_attributes():
    result = evaluate(params={"x": '<script type="text/javascript">pwn()</script>'})
    assert _has_check(result, "XSS-001")


def test_001_severity_is_critical():
    result = evaluate(params={"x": "<script>alert(1)</script>"})
    crits = [f for f in result.findings if f.check_id == "XSS-001"]
    assert all(f.severity == "CRITICAL" for f in crits)


def test_001_evidence_truncated():
    long_payload = "<script>" + "A" * 200 + "</script>"
    result = evaluate(params={"x": long_payload})
    for f in result.findings:
        if f.check_id == "XSS-001":
            assert len(f.evidence) <= 100


# ===========================================================================
# XSS-002: DOM-BASED XSS SINKS
# ===========================================================================

def test_002_document_write():
    result = evaluate(params={"q": "document.write('<img src=x>')"})
    assert _has_check(result, "XSS-002")


def test_002_document_write_spaces():
    result = evaluate(params={"q": "document.write  ( x )"})
    assert _has_check(result, "XSS-002")


def test_002_inner_html():
    result = evaluate(params={"html": "el.innerHTML = '<b>XSS</b>'"})
    assert _has_check(result, "XSS-002")


def test_002_inner_html_no_spaces():
    result = evaluate(params={"html": "el.innerHTML='<b>XSS</b>'"})
    assert _has_check(result, "XSS-002")


def test_002_outer_html():
    result = evaluate(params={"html": "el.outerHTML='<script>alert(1)</script>'"})
    assert _has_check(result, "XSS-002")


def test_002_eval_basic():
    result = evaluate(params={"cb": "eval('alert(1)')"})
    assert _has_check(result, "XSS-002")


def test_002_eval_uppercase():
    result = evaluate(params={"cb": "EVAL('alert(1)')"})
    assert _has_check(result, "XSS-002")


def test_002_set_timeout():
    result = evaluate(params={"timer": "setTimeout(function(){alert(1)}, 0)"})
    assert _has_check(result, "XSS-002")


def test_002_set_interval():
    result = evaluate(params={"timer": "setInterval(function(){steal()}, 1000)"})
    assert _has_check(result, "XSS-002")


def test_002_function_constructor():
    result = evaluate(params={"fn": "Function('alert(1)')()"})
    assert _has_check(result, "XSS-002")


def test_002_function_uppercase():
    result = evaluate(params={"fn": "FUNCTION('alert(1)')()"})
    assert _has_check(result, "XSS-002")


def test_002_severity_is_high():
    result = evaluate(params={"q": "eval('x')"})
    highs = [f for f in result.findings if f.check_id == "XSS-002"]
    assert all(f.severity == "HIGH" for f in highs)


def test_002_in_body():
    result = evaluate(body="document.write(userInput)")
    assert _has_check(result, "XSS-002")


def test_002_weight():
    result = evaluate(params={"q": "eval('x')"})
    assert result.risk_score == _CHECK_WEIGHTS["XSS-002"]


def test_002_not_triggered_by_evaluate_word():
    """The word 'evaluate' should not trigger XSS-002 (eval must be a word boundary)."""
    result = evaluate(params={"action": "evaluate the proposal"})
    assert not _has_check(result, "XSS-002")


# ===========================================================================
# XSS-003: CSS-BASED XSS
# ===========================================================================

def test_003_expression():
    result = evaluate(params={"style": "width:expression(alert(1))"})
    assert _has_check(result, "XSS-003")


def test_003_expression_spaces():
    result = evaluate(params={"style": "width:expression  (alert(1))"})
    assert _has_check(result, "XSS-003")


def test_003_url_javascript():
    result = evaluate(params={"css": "background:url(javascript:alert(1))"})
    assert _has_check(result, "XSS-003")


def test_003_url_javascript_spaces():
    result = evaluate(params={"css": "background: url( javascript:alert(1) )"})
    assert _has_check(result, "XSS-003")


def test_003_behavior_url():
    result = evaluate(params={"style": "-binding:behavior:url(#evil)"})
    assert _has_check(result, "XSS-003")


def test_003_at_import():
    result = evaluate(params={"style": "@import url('evil.css')"})
    assert _has_check(result, "XSS-003")


def test_003_at_import_uppercase():
    result = evaluate(params={"style": "@IMPORT url('evil.css')"})
    assert _has_check(result, "XSS-003")


def test_003_moz_binding():
    result = evaluate(params={"style": "-moz-binding:url('evil.xml#xss')"})
    assert _has_check(result, "XSS-003")


def test_003_severity_is_high():
    result = evaluate(params={"style": "expression(alert(1))"})
    highs = [f for f in result.findings if f.check_id == "XSS-003"]
    assert all(f.severity == "HIGH" for f in highs)


def test_003_in_header():
    result = evaluate(headers={"X-Custom-Style": "expression(alert(1))"})
    assert _has_check(result, "XSS-003")


def test_003_weight():
    result = evaluate(params={"style": "expression(x)"})
    assert result.risk_score == _CHECK_WEIGHTS["XSS-003"]


# ===========================================================================
# XSS-004: EVENT HANDLER INJECTION
# ===========================================================================

def test_004_onerror():
    result = evaluate(params={"img": '<img src=x onerror=alert(1)>'})
    assert _has_check(result, "XSS-004")


def test_004_onload():
    result = evaluate(params={"body": '<body onload=alert(1)>'})
    assert _has_check(result, "XSS-004")


def test_004_onclick():
    result = evaluate(params={"btn": '<button onclick="steal()">Click</button>'})
    assert _has_check(result, "XSS-004")


def test_004_onmouseover():
    result = evaluate(params={"div": '<div onmouseover="alert(document.cookie)">'})
    assert _has_check(result, "XSS-004")


def test_004_onfocus():
    result = evaluate(params={"input": '<input onfocus=alert(1) autofocus>'})
    assert _has_check(result, "XSS-004")


def test_004_onkeypress():
    result = evaluate(params={"input": '<input onkeypress=keylogger(event)>'})
    assert _has_check(result, "XSS-004")


def test_004_uppercase_handler():
    result = evaluate(params={"x": 'ONERROR=alert(1)'})
    assert _has_check(result, "XSS-004")


def test_004_with_spaces_around_equals():
    result = evaluate(params={"x": 'onerror = alert(1)'})
    assert _has_check(result, "XSS-004")


def test_004_severity_is_high():
    result = evaluate(params={"x": 'onerror=alert(1)'})
    highs = [f for f in result.findings if f.check_id == "XSS-004"]
    assert all(f.severity == "HIGH" for f in highs)


def test_004_in_body():
    result = evaluate(body="<div onmouseover=steal()>hover me</div>")
    assert _has_check(result, "XSS-004")


def test_004_ondblclick():
    result = evaluate(params={"x": 'ondblclick=alert(1)'})
    assert _has_check(result, "XSS-004")


def test_004_weight():
    result = evaluate(params={"x": 'onclick=alert(1)'})
    assert result.risk_score == _CHECK_WEIGHTS["XSS-004"]


# ===========================================================================
# XSS-005: SVG/HTML5 XSS VECTORS
# ===========================================================================

def test_005_svg_tag():
    result = evaluate(params={"html": '<svg onload=alert(1)>'})
    assert _has_check(result, "XSS-005")
    assert result.blocked is True


def test_005_svg_with_script():
    result = evaluate(params={"html": '<svg><script>alert(1)</script></svg>'})
    assert _has_check(result, "XSS-005")


def test_005_iframe():
    result = evaluate(params={"html": '<iframe src="javascript:alert(1)">'})
    assert _has_check(result, "XSS-005")


def test_005_iframe_closed():
    result = evaluate(params={"x": '<iframe></iframe>'})
    assert _has_check(result, "XSS-005")


def test_005_object_tag():
    result = evaluate(params={"html": '<object data="evil.swf">'})
    assert _has_check(result, "XSS-005")


def test_005_embed_tag():
    result = evaluate(params={"html": '<embed src="evil.swf">'})
    assert _has_check(result, "XSS-005")


def test_005_img_onerror():
    result = evaluate(params={"html": '<img src="x" onerror="alert(1)">'})
    assert _has_check(result, "XSS-005")


def test_005_img_onerror_no_quotes():
    result = evaluate(params={"html": "<img src=x onerror=alert(1)>"})
    assert _has_check(result, "XSS-005")


def test_005_details_tag():
    result = evaluate(params={"html": "<details ontoggle=alert(1)>"})
    assert _has_check(result, "XSS-005")


def test_005_body_onload():
    result = evaluate(params={"html": "<body onload=alert(1)>"})
    assert _has_check(result, "XSS-005")


def test_005_marquee_tag():
    result = evaluate(params={"html": "<marquee onstart=alert(1)>"})
    assert _has_check(result, "XSS-005")


def test_005_uppercase_svg():
    result = evaluate(params={"html": "<SVG onload=alert(1)>"})
    assert _has_check(result, "XSS-005")


def test_005_severity_is_critical():
    result = evaluate(params={"html": "<svg onload=alert(1)>"})
    crits = [f for f in result.findings if f.check_id == "XSS-005"]
    assert all(f.severity == "CRITICAL" for f in crits)


def test_005_in_body():
    result = evaluate(body="<iframe src='javascript:void(0)'></iframe>")
    assert _has_check(result, "XSS-005")


def test_005_weight():
    result = evaluate(params={"x": "<svg onload=x>"})
    assert result.risk_score >= _CHECK_WEIGHTS["XSS-005"]


# ===========================================================================
# XSS-006: URL/PERCENT-ENCODED XSS BYPASS
# ===========================================================================

def test_006_url_encoded_script_tag():
    """
    %3Cscript%3Ealert(1)%3C/script%3E decodes to <script>alert(1)</script>.
    Raw does not trigger XSS-001; decoded does.
    """
    encoded = "%3Cscript%3Ealert(1)%3C%2Fscript%3E"
    result = evaluate(params={"q": encoded})
    assert _has_check(result, "XSS-006")


def test_006_url_encoded_javascript_scheme():
    """javascript: URL-encoded as %6Aavascript: (only j is encoded)."""
    result = evaluate(params={"url": "%6Aavascript:alert(1)"})
    assert _has_check(result, "XSS-006")


def test_006_url_encoded_onerror():
    encoded = "%6Fnerror%3Dalert(1)"  # onerror=alert(1)
    result = evaluate(params={"x": encoded})
    assert _has_check(result, "XSS-006")


def test_006_url_encoded_svg():
    """
    %3Csvg%20onload%3Dalert(1)%3E decodes to <svg onload=alert(1)>.
    """
    encoded = "%3Csvg%20onload%3Dalert(1)%3E"
    result = evaluate(params={"html": encoded})
    assert _has_check(result, "XSS-006")


def test_006_not_fired_if_raw_already_triggered_001():
    """If raw triggers XSS-001, XSS-006 should not fire for that same check."""
    # <script> in raw form — XSS-001 fires, XSS-006 should not fire for XSS-001
    result = evaluate(params={"q": "<script>alert(1)</script>"})
    assert _has_check(result, "XSS-001")
    # XSS-006 may or may not fire for other decoded triggers, but not for 001
    # In this case value has no URL encoding, so decoded == raw => XSS-006 skipped
    assert not _has_check(result, "XSS-006")


def test_006_plain_text_no_encoding_no_trigger():
    """No URL encoding present — XSS-006 should not fire."""
    result = evaluate(params={"q": "hello world"})
    assert not _has_check(result, "XSS-006")


def test_006_severity_is_high():
    encoded = "%3Cscript%3Ealert(1)%3C/script%3E"
    result = evaluate(params={"q": encoded})
    highs = [f for f in result.findings if f.check_id == "XSS-006"]
    assert all(f.severity == "HIGH" for f in highs)


def test_006_weight():
    encoded = "%3Cscript%3Ealert(1)%3C/script%3E"
    result = evaluate(params={"q": encoded})
    assert _CHECK_WEIGHTS["XSS-006"] in [
        result.risk_score - sum(_CHECK_WEIGHTS[c] for c in _check_ids(result) if c != "XSS-006"),
        result.risk_score,
    ]


def test_006_url_encoded_iframe():
    encoded = "%3Ciframe%20src%3Djavascript%3Aalert(1)%3E"
    result = evaluate(params={"x": encoded})
    assert _has_check(result, "XSS-006")


# ===========================================================================
# XSS-007: HTML ENTITY / DOUBLE-ENCODED XSS
# ===========================================================================

def test_007_hex_entity_lt():
    """&#x3C; is the HTML entity for <."""
    result = evaluate(params={"q": "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;"})
    assert _has_check(result, "XSS-007")


def test_007_hex_entity_lt_uppercase():
    result = evaluate(params={"q": "&#x3c;script&#x3e;alert(1)"})
    assert _has_check(result, "XSS-007")


def test_007_decimal_entity_60():
    """&#60; is the decimal HTML entity for <."""
    result = evaluate(params={"q": "&#60;script&#62;alert(1)"})
    assert _has_check(result, "XSS-007")


def test_007_double_percent_encoded():
    """%253C is double percent-encoded <."""
    result = evaluate(params={"q": "%253Cscript%253Ealert(1)"})
    assert _has_check(result, "XSS-007")


def test_007_unicode_escape_lt():
    r"""\\u003C is a unicode escape for <."""
    result = evaluate(params={"q": r"\u003Cscript\u003Ealert(1)"})
    assert _has_check(result, "XSS-007")


def test_007_hex_entity_gt():
    """&#x3E; is the HTML entity for >."""
    result = evaluate(params={"q": "test&#x3E;content"})
    assert _has_check(result, "XSS-007")


def test_007_hex_entity_double_quote():
    """&#x22; is the HTML entity for "."""
    result = evaluate(params={"q": 'attr=&#x22;value&#x22;'})
    assert _has_check(result, "XSS-007")


def test_007_decimal_entity_34():
    """&#34; is the decimal HTML entity for "."""
    result = evaluate(params={"q": '&#34;injected&#34;'})
    assert _has_check(result, "XSS-007")


def test_007_hex_entity_slash():
    """&#x2F; is the HTML entity for /."""
    result = evaluate(params={"q": "&#x2F;etc&#x2F;passwd"})
    assert _has_check(result, "XSS-007")


def test_007_severity_is_high():
    result = evaluate(params={"q": "&#x3C;script&#x3E;alert(1)"})
    highs = [f for f in result.findings if f.check_id == "XSS-007"]
    assert all(f.severity == "HIGH" for f in highs)


def test_007_in_body():
    result = evaluate(body="&#60;script&#62;alert(1)&#60;/script&#62;")
    assert _has_check(result, "XSS-007")


def test_007_in_header():
    result = evaluate(headers={"X-Forwarded-For": "&#x3C;script&#x3E;xss"})
    assert _has_check(result, "XSS-007")


def test_007_double_percent_003c():
    result = evaluate(params={"x": "%253Cscript%253E"})
    assert _has_check(result, "XSS-007")


def test_007_unicode_escape_003c():
    result = evaluate(params={"x": r"\u003Cscript\u003E"})
    assert _has_check(result, "XSS-007")


def test_007_weight():
    result = evaluate(params={"x": "&#x3C;script&#x3E;"})
    assert _CHECK_WEIGHTS["XSS-007"] <= result.risk_score <= 100


def test_007_clean_safe_entity():
    """Named HTML entities like &amp; should not trigger XSS-007 (no &#xx; pattern)."""
    result = evaluate(params={"q": "&amp;safe&lt;text&gt;"})
    assert not _has_check(result, "XSS-007")


# ===========================================================================
# RISK SCORE AND BLOCKED FLAG TESTS
# ===========================================================================

def test_risk_score_single_critical():
    """Single CRITICAL check (XSS-001) contributes its weight."""
    result = evaluate(params={"q": "<script>alert(1)</script>"})
    assert result.risk_score == _CHECK_WEIGHTS["XSS-001"]


def test_risk_score_single_high():
    """Single HIGH check (XSS-002) contributes its weight."""
    result = evaluate(params={"q": "eval('x')"})
    assert result.risk_score == _CHECK_WEIGHTS["XSS-002"]


def test_risk_score_capped_at_100():
    """Risk score must not exceed 100 even with many checks firing."""
    # Fire all 7 checks: 45+30+25+30+45+25+25 = 225 — must be capped at 100
    combined = (
        "<script>alert(1)</script> "      # XSS-001
        "eval('x') "                       # XSS-002
        "expression(alert(1)) "            # XSS-003
        "onerror=alert(1) "                # XSS-004
        "<svg onload=alert(1)> "           # XSS-005
        "&#x3C;script&#x3E; "             # XSS-007
    )
    # Add URL-encoded payload to trigger XSS-006 without raw XSS-001/004/005
    # Use a separate param for XSS-006
    result = evaluate(
        params={"a": combined},
        body="%3Cscript%3Ealert(1)",        # XSS-006 candidate (encoded only)
    )
    assert result.risk_score <= 100


def test_risk_score_deduplication():
    """Same check ID across multiple params only counted once in risk score."""
    result = evaluate(params={
        "a": "<script>alert(1)</script>",
        "b": "<script>alert(2)</script>",
    })
    # XSS-001 fires for both params but weight counted once
    assert result.risk_score == _CHECK_WEIGHTS["XSS-001"]


def test_blocked_true_on_critical():
    result = evaluate(params={"q": "<script>alert(1)</script>"})
    assert result.blocked is True


def test_blocked_true_on_svg():
    result = evaluate(params={"q": "<svg onload=alert(1)>"})
    assert result.blocked is True


def test_blocked_false_on_high_only():
    """HIGH severity alone should not set blocked when threshold is CRITICAL."""
    result = evaluate(params={"q": "eval('x')"}, block_on_severity="CRITICAL")
    assert result.blocked is False


def test_blocked_true_when_threshold_high():
    """Set block_on_severity=HIGH — HIGH findings should set blocked=True."""
    result = evaluate(
        params={"q": "eval('x')"},
        block_on_severity="HIGH",
    )
    assert result.blocked is True


def test_blocked_false_clean():
    result = evaluate(params={"q": "hello"})
    assert result.blocked is False


# ===========================================================================
# XSSRESULT METHODS
# ===========================================================================

def test_to_dict_structure():
    result = evaluate(params={"q": "<script>alert(1)</script>"})
    d = result.to_dict()
    assert "findings" in d
    assert "risk_score" in d
    assert "blocked" in d
    assert isinstance(d["findings"], list)
    assert isinstance(d["risk_score"], int)
    assert isinstance(d["blocked"], bool)


def test_to_dict_finding_fields():
    result = evaluate(params={"q": "<script>alert(1)</script>"})
    d = result.to_dict()
    for finding in d["findings"]:
        assert "check_id" in finding
        assert "severity" in finding
        assert "title" in finding
        assert "detail" in finding
        assert "weight" in finding
        assert "parameter" in finding
        assert "evidence" in finding


def test_summary_clean():
    result = evaluate(params={"q": "hello"})
    assert "CLEAN" in result.summary()
    assert "risk_score=0" in result.summary()


def test_summary_blocked():
    result = evaluate(params={"q": "<script>alert(1)</script>"})
    assert "BLOCKED" in result.summary()
    assert "XSS-001" in result.summary()


def test_summary_flagged():
    result = evaluate(params={"q": "eval('x')"}, block_on_severity="CRITICAL")
    assert "FLAGGED" in result.summary()
    assert "XSS-002" in result.summary()


def test_by_severity_grouping():
    result = evaluate(params={
        "a": "<script>alert(1)</script>",  # CRITICAL
        "b": "eval('x')",                  # HIGH
    })
    groups = result.by_severity()
    assert "CRITICAL" in groups
    assert "HIGH" in groups
    assert all(f.severity == "CRITICAL" for f in groups["CRITICAL"])
    assert all(f.severity == "HIGH" for f in groups["HIGH"])


def test_by_severity_empty_on_clean():
    result = evaluate(params={"q": "hello"})
    assert result.by_severity() == {}


# ===========================================================================
# EVALUATE_MANY
# ===========================================================================

def test_evaluate_many_empty():
    results = evaluate_many([])
    assert results == []


def test_evaluate_many_single_clean():
    results = evaluate_many([{"params": {"q": "hello"}}])
    assert len(results) == 1
    assert _clean(results[0])


def test_evaluate_many_single_xss():
    results = evaluate_many([{"params": {"q": "<script>alert(1)</script>"}}])
    assert len(results) == 1
    assert _has_check(results[0], "XSS-001")


def test_evaluate_many_multiple():
    requests = [
        {"params": {"q": "hello"}},
        {"params": {"q": "<script>alert(1)</script>"}},
        {"params": {"q": "eval('x')"}},
    ]
    results = evaluate_many(requests)
    assert len(results) == 3
    assert _clean(results[0])
    assert _has_check(results[1], "XSS-001")
    assert _has_check(results[2], "XSS-002")


def test_evaluate_many_block_on_severity():
    results = evaluate_many([{
        "params": {"q": "eval('x')"},
        "block_on_severity": "HIGH",
    }])
    assert results[0].blocked is True


def test_evaluate_many_preserves_order():
    """Results must be in same order as input requests."""
    requests = [{"params": {"q": f"param_{i}"}} for i in range(10)]
    requests[3]["params"]["q"] = "<script>alert(1)</script>"
    results = evaluate_many(requests)
    assert len(results) == 10
    assert _has_check(results[3], "XSS-001")
    for i, res in enumerate(results):
        if i != 3:
            assert _clean(res)


def test_evaluate_many_with_body():
    results = evaluate_many([{"body": "<svg onload=alert(1)>"}])
    assert _has_check(results[0], "XSS-005")


def test_evaluate_many_with_headers():
    results = evaluate_many([{"headers": {"X-Inject": "<script>x</script>"}}])
    assert _has_check(results[0], "XSS-001")


# ===========================================================================
# COMBINED / MULTI-VECTOR ATTACKS
# ===========================================================================

def test_combined_001_and_004():
    """Payload triggers both reflected XSS and event handler injection."""
    result = evaluate(params={"q": '<img src=x onerror=alert(1)><script>x</script>'})
    assert _has_check(result, "XSS-001")
    assert _has_check(result, "XSS-004")


def test_combined_001_and_005():
    """<script> and <svg> in same payload fires both XSS-001 and XSS-005."""
    result = evaluate(params={"q": '<script>x</script><svg onload=alert(1)>'})
    assert _has_check(result, "XSS-001")
    assert _has_check(result, "XSS-005")


def test_combined_002_and_003():
    """DOM sink and CSS expression in same payload."""
    result = evaluate(params={
        "cb": "eval('x')",
        "style": "expression(alert(1))",
    })
    assert _has_check(result, "XSS-002")
    assert _has_check(result, "XSS-003")


def test_combined_005_and_004():
    """SVG + onerror in same value."""
    result = evaluate(params={"x": '<svg><img onerror=alert(1)></svg>'})
    assert _has_check(result, "XSS-005")
    assert _has_check(result, "XSS-004")


def test_combined_risk_score_two_checks():
    """Two unique checks fired — risk score = sum of both weights."""
    result = evaluate(params={
        "a": "eval('x')",     # XSS-002 w=30
        "b": "expression(1)", # XSS-003 w=25
    })
    assert result.risk_score == _CHECK_WEIGHTS["XSS-002"] + _CHECK_WEIGHTS["XSS-003"]


def test_multiple_params_same_check_once_in_score():
    """XSS-001 from three params still contributes weight only once."""
    result = evaluate(params={
        "a": "<script>1</script>",
        "b": "<script>2</script>",
        "c": "javascript:alert(3)",
    })
    assert result.risk_score == _CHECK_WEIGHTS["XSS-001"]


# ===========================================================================
# PARAMETER SOURCE TRACKING
# ===========================================================================

def test_finding_parameter_name_from_params():
    result = evaluate(params={"my_param": "<script>alert(1)</script>"})
    findings_001 = [f for f in result.findings if f.check_id == "XSS-001"]
    assert any(f.parameter == "my_param" for f in findings_001)


def test_finding_parameter_name_from_headers():
    result = evaluate(headers={"User-Agent": "eval('x')"})
    findings_002 = [f for f in result.findings if f.check_id == "XSS-002"]
    assert any(f.parameter == "User-Agent" for f in findings_002)


def test_finding_parameter_name_from_body():
    result = evaluate(body="<script>alert(1)</script>")
    findings_001 = [f for f in result.findings if f.check_id == "XSS-001"]
    assert any(f.parameter == "body" for f in findings_001)


# ===========================================================================
# CHECK WEIGHTS DICT
# ===========================================================================

def test_check_weights_all_keys_present():
    required = {"XSS-001", "XSS-002", "XSS-003", "XSS-004", "XSS-005", "XSS-006", "XSS-007"}
    assert required == set(_CHECK_WEIGHTS.keys())


def test_check_weights_values():
    assert _CHECK_WEIGHTS["XSS-001"] == 45
    assert _CHECK_WEIGHTS["XSS-002"] == 30
    assert _CHECK_WEIGHTS["XSS-003"] == 25
    assert _CHECK_WEIGHTS["XSS-004"] == 30
    assert _CHECK_WEIGHTS["XSS-005"] == 45
    assert _CHECK_WEIGHTS["XSS-006"] == 25
    assert _CHECK_WEIGHTS["XSS-007"] == 25


# ===========================================================================
# EDGE CASES
# ===========================================================================

def test_none_params_none_headers_none_body():
    result = evaluate(None, None, None)
    assert _clean(result)
    assert result.risk_score == 0


def test_body_only():
    result = evaluate(body="<script>alert(1)</script>")
    assert _has_check(result, "XSS-001")


def test_headers_only():
    result = evaluate(headers={"X-Header": "<script>alert(1)</script>"})
    assert _has_check(result, "XSS-001")


def test_params_with_none_like_string():
    """The literal string 'None' should not trigger any checks."""
    result = evaluate(params={"val": "None"})
    assert _clean(result)


def test_very_long_clean_value():
    """A very long clean value should not cause errors."""
    result = evaluate(params={"text": "A" * 10000})
    assert _clean(result)


def test_evidence_max_length_all_checks():
    """Evidence must be at most 100 chars for every finding."""
    payload = (
        "<script>" + "X" * 200 + "</script> "
        "eval(" + "Y" * 200 + ") "
        "expression(" + "Z" * 200 + ") "
        "onerror=" + "W" * 200 + " "
        "<svg>" + "V" * 200
    )
    result = evaluate(params={"x": payload})
    for f in result.findings:
        assert len(f.evidence) <= 100, (
            f"Evidence for {f.check_id} exceeds 100 chars: {len(f.evidence)}"
        )


def test_unicode_safe_input():
    """Non-ASCII safe content should not trigger any checks."""
    result = evaluate(params={"greeting": "Olá, João! — こんにちは"})
    assert _clean(result)


def test_empty_string_param_value():
    result = evaluate(params={"q": ""})
    assert _clean(result)


def test_whitespace_only_body():
    result = evaluate(body="   \n\t  ")
    assert _clean(result)


def test_multiline_body_with_xss():
    """XSS in multi-line body should still be detected."""
    body = "line1\nline2\n<script>alert(1)</script>\nline4"
    result = evaluate(body=body)
    assert _has_check(result, "XSS-001")


def test_007_no_false_positive_on_numeric_entity():
    """&#65; is 'A' — not a dangerous char — should NOT trigger XSS-007."""
    result = evaluate(params={"q": "&#65;&#66;&#67;"})  # ABC
    assert not _has_check(result, "XSS-007")


def test_002_setinterval_fires():
    result = evaluate(params={"x": "setInterval(malicious, 500)"})
    assert _has_check(result, "XSS-002")


def test_003_moz_binding_with_spaces():
    result = evaluate(params={"style": "-moz-binding :   url('evil.xml')"})
    assert _has_check(result, "XSS-003")


def test_005_embed_with_caps():
    result = evaluate(params={"x": "<EMBED src='evil.swf'>"})
    assert _has_check(result, "XSS-005")


def test_001_javascript_scheme_in_body():
    result = evaluate(body="Please click: javascript:alert(document.domain)")
    assert _has_check(result, "XSS-001")


def test_finding_dataclass_fields():
    """XSSFinding instances must have all required fields populated."""
    result = evaluate(params={"q": "<script>alert(1)</script>"})
    for f in result.findings:
        assert isinstance(f.check_id, str) and f.check_id
        assert isinstance(f.severity, str) and f.severity
        assert isinstance(f.title, str) and f.title
        assert isinstance(f.detail, str) and f.detail
        assert isinstance(f.weight, int) and f.weight > 0
        assert isinstance(f.parameter, str)
        assert isinstance(f.evidence, str)
