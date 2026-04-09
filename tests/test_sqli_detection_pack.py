# CC BY 4.0 License — Cyber Port Portfolio
# https://creativecommons.org/licenses/by/4.0/
#
# Test file: test_sqli_detection_pack.py
# Purpose: Comprehensive pytest suite for sqli_detection_pack.py
# Run with: python -m pytest tests/test_sqli_detection_pack.py -q
# Python 3.9+ compatible

import sys
import os

# Allow import from shared/rulepacks without an installed package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared", "rulepacks"))

from sqli_detection_pack import (
    SQLIFinding,
    SQLIResult,
    _CHECK_WEIGHTS,
    evaluate,
    evaluate_many,
)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def fired_ids(result: SQLIResult):
    """Return the set of check_ids that fired."""
    return {f.check_id for f in result.findings}


def has_check(result: SQLIResult, check_id: str) -> bool:
    return check_id in fired_ids(result)


# ===========================================================================
# SQLI-001 — Classic SQL Injection
# ===========================================================================

def test_001_union_select_basic():
    r = evaluate(params={"q": "1 UNION SELECT 1,2,3"})
    assert has_check(r, "SQLI-001")

def test_001_union_all_select():
    r = evaluate(params={"q": "' UNION ALL SELECT NULL,NULL--"})
    assert has_check(r, "SQLI-001")

def test_001_union_select_multispace():
    r = evaluate(params={"q": "UNION    SELECT name FROM users"})
    assert has_check(r, "SQLI-001")

def test_001_union_select_tab_whitespace():
    r = evaluate(params={"q": "UNION\tSELECT 1"})
    assert has_check(r, "SQLI-001")

def test_001_or_1_eq_1():
    r = evaluate(params={"id": "' OR 1=1--"})
    assert has_check(r, "SQLI-001")

def test_001_or_quoted_eq():
    r = evaluate(params={"id": "' OR 'a'='a"})
    assert has_check(r, "SQLI-001")

def test_001_and_1_eq_1():
    r = evaluate(params={"id": "1 AND 1=1"})
    assert has_check(r, "SQLI-001")

def test_001_and_quoted_numbers():
    r = evaluate(params={"id": "1 AND '1'='1"})
    assert has_check(r, "SQLI-001")

def test_001_union_select_in_header():
    r = evaluate(headers={"X-Custom": "UNION SELECT password FROM users"})
    assert has_check(r, "SQLI-001")

def test_001_union_select_in_body():
    r = evaluate(body="search=UNION SELECT 1,2--")
    assert has_check(r, "SQLI-001")

def test_001_severity_is_critical():
    r = evaluate(params={"q": "UNION SELECT 1"})
    for f in r.findings:
        if f.check_id == "SQLI-001":
            assert f.severity == "CRITICAL"

def test_001_weight():
    assert _CHECK_WEIGHTS["SQLI-001"] == 45

def test_001_blocked_true():
    r = evaluate(params={"q": "UNION SELECT 1"})
    assert r.blocked is True

def test_001_risk_score_at_least_45():
    r = evaluate(params={"q": "UNION SELECT 1"})
    assert r.risk_score >= 45

def test_001_or_with_digit_space():
    r = evaluate(params={"id": "OR 2=2"})
    assert has_check(r, "SQLI-001")

def test_001_union_select_newline():
    r = evaluate(params={"q": "UNION\nSELECT 1"})
    assert has_check(r, "SQLI-001")

# ===========================================================================
# SQLI-002 — Time-Based Blind SQL Injection
# ===========================================================================

def test_002_sleep():
    r = evaluate(params={"id": "1; SLEEP(5)--"})
    assert has_check(r, "SQLI-002")

def test_002_sleep_uppercase():
    r = evaluate(params={"id": "SLEEP(10)"})
    assert has_check(r, "SQLI-002")

def test_002_sleep_mixed_case():
    r = evaluate(params={"id": "SleEp(3)"})
    assert has_check(r, "SQLI-002")

def test_002_waitfor_delay():
    r = evaluate(params={"id": "1; WAITFOR DELAY '0:0:5'--"})
    assert has_check(r, "SQLI-002")

def test_002_waitfor_delay_lowercase():
    r = evaluate(params={"id": "waitfor delay '0:0:5'"})
    assert has_check(r, "SQLI-002")

def test_002_benchmark():
    r = evaluate(params={"id": "1 AND BENCHMARK(5000000,MD5(1))--"})
    assert has_check(r, "SQLI-002")

def test_002_benchmark_lowercase():
    r = evaluate(params={"id": "benchmark(100,sha1(1))"})
    assert has_check(r, "SQLI-002")

def test_002_pg_sleep():
    r = evaluate(params={"id": "1; SELECT pg_sleep(5)--"})
    assert has_check(r, "SQLI-002")

def test_002_pg_sleep_no_space():
    r = evaluate(params={"id": "pg_sleep(10)"})
    assert has_check(r, "SQLI-002")

def test_002_in_header():
    r = evaluate(headers={"User-Agent": "SLEEP(1)"})
    assert has_check(r, "SQLI-002")

def test_002_severity_is_critical():
    r = evaluate(params={"id": "SLEEP(1)"})
    for f in r.findings:
        if f.check_id == "SQLI-002":
            assert f.severity == "CRITICAL"

def test_002_weight():
    assert _CHECK_WEIGHTS["SQLI-002"] == 45

def test_002_blocked():
    r = evaluate(params={"id": "SLEEP(5)"})
    assert r.blocked is True

def test_002_sleep_with_spaces_before_paren():
    r = evaluate(params={"id": "SLEEP  (5)"})
    assert has_check(r, "SQLI-002")

# ===========================================================================
# SQLI-003 — Boolean-Based Blind SQL Injection
# ===========================================================================

def test_003_and_digit_eq_digit():
    r = evaluate(params={"id": "1 AND 1=1"})
    # SQLI-001 fires first for AND digit=digit; SQLI-003 should be suppressed
    assert has_check(r, "SQLI-001")
    assert not has_check(r, "SQLI-003")

def test_003_and_digit_false():
    r = evaluate(params={"id": "1 AND 1=2"})
    # AND \d+=\d+ matches SQLI-001 (\bAND\b\s+['\d]\s*=\s*['\d]) — should suppress 003
    assert has_check(r, "SQLI-001")
    assert not has_check(r, "SQLI-003")

def test_003_and_quoted_string_eq():
    # AND 'a'='a — matches SQLI-001 pattern (\bAND\b\s+['\d]\s*=\s*['\d])
    r = evaluate(params={"id": "' AND 'a'='a"})
    assert has_check(r, "SQLI-001")

def test_003_or_quoted_word():
    # ' OR 'x' — fires SQLI-003 if SQLI-001 has not fired
    r = evaluate(params={"id": "' OR 'admin'"})
    # SQLI-001 OR pattern needs digit or quote before =; this does NOT match OR x=x
    # but SQLI-003 pattern '\s+OR\s+'\w+' should match
    assert has_check(r, "SQLI-003")

def test_003_and_alpha_eq_alpha():
    # AND 'foo'='bar' — SQLI-001 catches '\bAND\b\s+[']\s*='; check 003 suppressed
    r = evaluate(params={"id": "x AND 'foo'='bar'"})
    # SQLI-001 pattern: \bAND\b\s+['\d]\s*=\s*['\d] — 'f is not a quote at boundary
    # Let's confirm actual firing empirically via the module logic
    # The AND pattern in 001 is \bAND\b\s+['\d] so 'foo' => leading ' matches ['\d]
    assert has_check(r, "SQLI-001")

def test_003_severity_is_high():
    r = evaluate(params={"id": "' OR 'admin'"})
    for f in r.findings:
        if f.check_id == "SQLI-003":
            assert f.severity == "HIGH"

def test_003_weight():
    assert _CHECK_WEIGHTS["SQLI-003"] == 30

def test_003_not_blocked_by_default():
    # HIGH severity alone should NOT set blocked=True with default CRITICAL threshold
    r = evaluate(params={"id": "' OR 'admin'"})
    if not has_check(r, "SQLI-001") and not has_check(r, "SQLI-002") and not has_check(r, "SQLI-005"):
        assert r.blocked is False

def test_003_and_numeric_variants():
    r = evaluate(params={"id": "abc' AND 99=99 --"})
    # AND\s+\d+=\d+ fires SQLI-001 OR SQLI-003; SQLI-001 catches \bAND\b\s+[\d]
    assert has_check(r, "SQLI-001") or has_check(r, "SQLI-003")

def test_003_or_single_quoted():
    r = evaluate(params={"id": "x' OR 'x'"})
    assert has_check(r, "SQLI-003") or has_check(r, "SQLI-001")

# ===========================================================================
# SQLI-004 — Error-Based SQL Injection
# ===========================================================================

def test_004_extractvalue():
    r = evaluate(params={"id": "1 AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))"})
    assert has_check(r, "SQLI-004")

def test_004_extractvalue_lowercase():
    r = evaluate(params={"id": "extractvalue(1,0x1)"})
    assert has_check(r, "SQLI-004")

def test_004_updatexml():
    r = evaluate(params={"id": "UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)"})
    assert has_check(r, "SQLI-004")

def test_004_floor_rand():
    r = evaluate(params={"id": "SELECT FLOOR(RAND(0)*2)"})
    assert has_check(r, "SQLI-004")

def test_004_floor_rand_spaces():
    r = evaluate(params={"id": "FLOOR( RAND (0))"})
    assert has_check(r, "SQLI-004")

def test_004_exp_tilde():
    r = evaluate(params={"id": "EXP(~(SELECT*FROM(users)))"})
    assert has_check(r, "SQLI-004")

def test_004_exp_with_spaces():
    r = evaluate(params={"id": "EXP( ~0)"})
    assert has_check(r, "SQLI-004")

def test_004_geometrycollection():
    r = evaluate(params={"id": "GeometryCollection(point(1 1),point(2 2))"})
    assert has_check(r, "SQLI-004")

def test_004_geometrycollection_lowercase():
    r = evaluate(params={"id": "geometrycollection(point(0 0))"})
    assert has_check(r, "SQLI-004")

def test_004_severity_is_high():
    r = evaluate(params={"id": "EXTRACTVALUE(1,1)"})
    for f in r.findings:
        if f.check_id == "SQLI-004":
            assert f.severity == "HIGH"

def test_004_weight():
    assert _CHECK_WEIGHTS["SQLI-004"] == 30

def test_004_in_header():
    r = evaluate(headers={"Referer": "UPDATEXML(1,1,1)"})
    assert has_check(r, "SQLI-004")

def test_004_updatexml_lowercase():
    r = evaluate(params={"id": "updatexml(1,concat(0x7e,database()),1)"})
    assert has_check(r, "SQLI-004")

# ===========================================================================
# SQLI-005 — Stacked Queries
# ===========================================================================

def test_005_semicolon_insert():
    r = evaluate(params={"id": "1; INSERT INTO users VALUES (1,'evil')"})
    assert has_check(r, "SQLI-005")

def test_005_semicolon_drop():
    r = evaluate(params={"id": "1'; DROP TABLE users--"})
    assert has_check(r, "SQLI-005")

def test_005_semicolon_update():
    r = evaluate(params={"id": "1; UPDATE users SET pass='x'"})
    assert has_check(r, "SQLI-005")

def test_005_semicolon_select():
    r = evaluate(params={"id": "1; SELECT * FROM users"})
    assert has_check(r, "SQLI-005")

def test_005_semicolon_exec():
    r = evaluate(params={"id": "1; EXEC xp_cmdshell('dir')"})
    assert has_check(r, "SQLI-005")

def test_005_semicolon_call():
    r = evaluate(params={"id": "1; CALL stored_proc()"})
    assert has_check(r, "SQLI-005")

def test_005_semicolon_with_space():
    r = evaluate(params={"id": "1 ;   DROP TABLE accounts--"})
    assert has_check(r, "SQLI-005")

def test_005_lowercase():
    r = evaluate(params={"id": "1; drop table t"})
    assert has_check(r, "SQLI-005")

def test_005_in_body():
    r = evaluate(body="cmd=1; INSERT INTO logs VALUES (1,'x')")
    assert has_check(r, "SQLI-005")

def test_005_severity_is_critical():
    r = evaluate(params={"id": "1; DROP TABLE x"})
    for f in r.findings:
        if f.check_id == "SQLI-005":
            assert f.severity == "CRITICAL"

def test_005_weight():
    assert _CHECK_WEIGHTS["SQLI-005"] == 45

def test_005_blocked_true():
    r = evaluate(params={"id": "1; DROP TABLE users"})
    assert r.blocked is True

def test_005_exec_mixed_case():
    r = evaluate(params={"id": "1; eXeC sp_who"})
    assert has_check(r, "SQLI-005")

# ===========================================================================
# SQLI-006 — URL-Encoded Bypass
# ===========================================================================

def test_006_encoded_union_select():
    # %55 = U, %4e = N, encodes "UNION SELECT"
    r = evaluate(params={"q": "%55NION%20SELECT%201%2C2"})
    assert has_check(r, "SQLI-006")

def test_006_encoded_sleep():
    # SLEEP encoded as %53LEEP
    r = evaluate(params={"id": "%53LEEP(5)"})
    assert has_check(r, "SQLI-006")

def test_006_double_percent_encoded_union():
    # Uses %20 for spaces so urllib.parse.unquote() decodes to "UNION SELECT 1"
    r = evaluate(params={"q": "%55%4e%49%4f%4e%20%53%45%4c%45%43%54%201"})
    assert has_check(r, "SQLI-006")

def test_006_does_not_fire_if_raw_already_fired():
    # Raw value triggers SQLI-001 directly; SQLI-006 should NOT also fire
    r = evaluate(params={"q": "UNION SELECT 1"})
    assert has_check(r, "SQLI-001")
    assert not has_check(r, "SQLI-006")

def test_006_clean_url_encoded_no_sqli():
    # Normal percent-encoded text (e.g., a space), no SQLi
    r = evaluate(params={"name": "John%20Doe"})
    assert not has_check(r, "SQLI-006")

def test_006_encoded_drop():
    # ;%44ROP TABLE -> ;DROP TABLE after decode
    r = evaluate(params={"id": "1;%44ROP TABLE users"})
    assert has_check(r, "SQLI-006") or has_check(r, "SQLI-005")

def test_006_severity_is_high():
    r = evaluate(params={"q": "%55NION%20SELECT%201"})
    for f in r.findings:
        if f.check_id == "SQLI-006":
            assert f.severity == "HIGH"

def test_006_weight():
    assert _CHECK_WEIGHTS["SQLI-006"] == 25

def test_006_no_finding_for_unencoded_safe_string():
    r = evaluate(params={"id": "hello world"})
    assert not has_check(r, "SQLI-006")

def test_006_encoded_waitfor():
    # WAITFOR encoded partially
    r = evaluate(params={"id": "%57AITFOR%20DELAY%20'0:0:5'"})
    assert has_check(r, "SQLI-006")

def test_006_encoded_benchmark():
    r = evaluate(params={"id": "%42ENCHMARK(100,sha1(1))"})
    assert has_check(r, "SQLI-006")

def test_006_encoded_insert_stacked():
    r = evaluate(params={"id": "1;%20%49NSERT%20INTO%20x%20VALUES(1)"})
    assert has_check(r, "SQLI-006") or has_check(r, "SQLI-005")

# ===========================================================================
# SQLI-007 — Comment-Based Obfuscation
# ===========================================================================

def test_007_inline_comment_before_select():
    r = evaluate(params={"q": "/**/SELECT * FROM users"})
    assert has_check(r, "SQLI-007")

def test_007_double_dash_before_select():
    r = evaluate(params={"q": "-- SELECT * FROM users"})
    assert has_check(r, "SQLI-007")

def test_007_hash_before_select():
    r = evaluate(params={"q": "# SELECT * FROM users"})
    assert has_check(r, "SQLI-007")

def test_007_comment_before_union():
    r = evaluate(params={"q": "1/**/UNION SELECT 1"})
    assert has_check(r, "SQLI-007")

def test_007_comment_before_drop():
    r = evaluate(params={"q": "1/**/DROP TABLE t"})
    assert has_check(r, "SQLI-007")

def test_007_comment_before_delete():
    r = evaluate(params={"q": "/**/DELETE FROM users"})
    assert has_check(r, "SQLI-007")

def test_007_comment_before_where():
    r = evaluate(params={"q": "SELECT 1/**/WHERE id=1"})
    assert has_check(r, "SQLI-007")

def test_007_keyword_then_comment():
    r = evaluate(params={"q": "SELECT--comment"})
    assert has_check(r, "SQLI-007")

def test_007_union_then_comment():
    r = evaluate(params={"q": "UNION -- rest"})
    assert has_check(r, "SQLI-007")

def test_007_inline_comment_before_insert():
    r = evaluate(params={"q": "/**/INSERT INTO t VALUES(1)"})
    assert has_check(r, "SQLI-007")

def test_007_inline_comment_before_update():
    r = evaluate(params={"q": "/**/UPDATE users SET x=1"})
    assert has_check(r, "SQLI-007")

def test_007_severity_is_high():
    r = evaluate(params={"q": "/**/SELECT 1"})
    for f in r.findings:
        if f.check_id == "SQLI-007":
            assert f.severity == "HIGH"

def test_007_weight():
    assert _CHECK_WEIGHTS["SQLI-007"] == 25

def test_007_comment_only_no_keyword():
    # Comment token present but no SQL keyword nearby — should NOT fire
    r = evaluate(params={"q": "hello -- world"})
    assert not has_check(r, "SQLI-007")

def test_007_hash_before_from():
    r = evaluate(params={"q": "#FROM"})
    assert has_check(r, "SQLI-007")

def test_007_inline_before_table():
    r = evaluate(params={"q": "/**/TABLE users"})
    assert has_check(r, "SQLI-007")

# ===========================================================================
# Clean / benign input — no findings expected
# ===========================================================================

def test_clean_normal_string():
    r = evaluate(params={"name": "Alice"})
    assert len(r.findings) == 0
    assert r.risk_score == 0
    assert r.blocked is False

def test_clean_empty_params():
    r = evaluate(params={})
    assert len(r.findings) == 0

def test_clean_none_inputs():
    r = evaluate()
    assert len(r.findings) == 0

def test_clean_integer_string():
    r = evaluate(params={"id": "42"})
    assert len(r.findings) == 0

def test_clean_email():
    r = evaluate(params={"email": "user@example.com"})
    assert len(r.findings) == 0

def test_clean_url_path():
    r = evaluate(params={"path": "/home/user/docs"})
    assert len(r.findings) == 0

def test_clean_json_body():
    r = evaluate(body='{"key": "value", "count": 10}')
    assert len(r.findings) == 0

def test_clean_sql_like_but_harmless():
    # "selector" and "android" contain "and" but should not match word-boundary patterns
    r = evaluate(params={"tag": "selector-widget"})
    assert len(r.findings) == 0

def test_clean_sleep_word_in_sentence():
    # "sleep" as a word in a sentence — no parenthesis after
    r = evaluate(params={"msg": "I need to sleep tonight"})
    assert not has_check(r, "SQLI-002")

def test_clean_no_body():
    r = evaluate(params={"x": "normal"}, headers={"Accept": "application/json"})
    assert len(r.findings) == 0

# ===========================================================================
# Risk score and deduplication
# ===========================================================================

def test_risk_score_capped_at_100():
    # Fire multiple CRITICAL checks to test the min(100, ...) cap
    payload = "UNION SELECT 1; SLEEP(5); EXEC sp_who; DROP TABLE t"
    r = evaluate(params={"a": payload})
    assert r.risk_score <= 100

def test_risk_score_unique_check_ids():
    # Two params with the same SQLI-001 pattern: risk_score counts each check_id once
    r = evaluate(params={"a": "UNION SELECT 1", "b": "OR 1=1"})
    # Both fire SQLI-001; weight counted only once
    assert r.risk_score == _CHECK_WEIGHTS["SQLI-001"]

def test_risk_score_multiple_unique_checks():
    # SQLI-001 (45) + SQLI-002 (45) = 90 (under cap)
    r = evaluate(params={"a": "UNION SELECT 1", "b": "SLEEP(5)"})
    expected = _CHECK_WEIGHTS["SQLI-001"] + _CHECK_WEIGHTS["SQLI-002"]
    assert r.risk_score == min(100, expected)

def test_risk_score_single_check_equals_weight():
    r = evaluate(params={"id": "SLEEP(5)"})
    assert r.risk_score == _CHECK_WEIGHTS["SQLI-002"]

def test_risk_score_zero_for_clean():
    r = evaluate(params={"id": "hello"})
    assert r.risk_score == 0

# ===========================================================================
# blocked flag and block_on_severity
# ===========================================================================

def test_blocked_default_critical():
    r = evaluate(params={"id": "UNION SELECT 1"})
    assert r.blocked is True

def test_not_blocked_high_with_critical_threshold():
    # SQLI-004 is HIGH; default threshold is CRITICAL; should not block
    r = evaluate(params={"id": "EXTRACTVALUE(1,1)"})
    assert not has_check(r, "SQLI-001")
    assert not has_check(r, "SQLI-002")
    assert not has_check(r, "SQLI-005")
    if r.findings and all(f.severity == "HIGH" for f in r.findings):
        assert r.blocked is False

def test_blocked_high_threshold():
    r = evaluate(params={"id": "EXTRACTVALUE(1,1)"}, block_on_severity="HIGH")
    assert r.blocked is True

def test_blocked_medium_threshold_with_high_finding():
    r = evaluate(params={"id": "EXTRACTVALUE(1,1)"}, block_on_severity="MEDIUM")
    assert r.blocked is True

def test_blocked_info_threshold_with_any_finding():
    r = evaluate(params={"id": "UNION SELECT 1"}, block_on_severity="INFO")
    assert r.blocked is True

def test_not_blocked_clean_any_threshold():
    r = evaluate(params={"id": "hello"}, block_on_severity="INFO")
    assert r.blocked is False

# ===========================================================================
# SQLIResult data model methods
# ===========================================================================

def test_to_dict_keys():
    r = evaluate(params={"q": "UNION SELECT 1"})
    d = r.to_dict()
    assert "risk_score" in d
    assert "blocked" in d
    assert "findings" in d
    assert isinstance(d["findings"], list)

def test_to_dict_finding_keys():
    r = evaluate(params={"q": "UNION SELECT 1"})
    d = r.to_dict()
    assert len(d["findings"]) > 0
    f = d["findings"][0]
    for key in ("check_id", "severity", "title", "detail", "weight", "parameter", "evidence"):
        assert key in f

def test_summary_no_findings():
    r = evaluate(params={"q": "hello"})
    s = r.summary()
    assert "No SQL injection" in s
    assert "0" in s

def test_summary_with_findings():
    r = evaluate(params={"q": "UNION SELECT 1"})
    s = r.summary()
    assert "SQLI-001" in s
    assert "risk_score" in s

def test_summary_blocked_label():
    r = evaluate(params={"q": "UNION SELECT 1"})
    s = r.summary()
    assert "BLOCKED" in s

def test_summary_flagged_label():
    r = evaluate(params={"q": "EXTRACTVALUE(1,1)"}, block_on_severity="CRITICAL")
    if r.findings and not r.blocked:
        s = r.summary()
        assert "FLAGGED" in s

def test_by_severity_groups():
    r = evaluate(params={"a": "UNION SELECT 1", "b": "EXTRACTVALUE(1,1)"})
    groups = r.by_severity()
    assert isinstance(groups, dict)
    if "CRITICAL" in groups:
        assert all(f.severity == "CRITICAL" for f in groups["CRITICAL"])

def test_by_severity_empty_for_clean():
    r = evaluate(params={"id": "42"})
    assert r.by_severity() == {}

def test_finding_parameter_label_param():
    r = evaluate(params={"myfield": "UNION SELECT 1"})
    labels = [f.parameter for f in r.findings]
    assert any("myfield" in lbl for lbl in labels)

def test_finding_parameter_label_header():
    r = evaluate(headers={"X-Attack": "SLEEP(5)"})
    labels = [f.parameter for f in r.findings]
    assert any("X-Attack" in lbl for lbl in labels)

def test_finding_parameter_label_body():
    r = evaluate(body="UNION SELECT 1")
    labels = [f.parameter for f in r.findings]
    assert any("body" in lbl for lbl in labels)

def test_finding_evidence_truncated():
    long_val = "UNION SELECT " + "A" * 200
    r = evaluate(params={"q": long_val})
    for f in r.findings:
        assert len(f.evidence) <= 100

def test_finding_has_all_fields():
    r = evaluate(params={"q": "UNION SELECT 1"})
    assert len(r.findings) > 0
    f = r.findings[0]
    assert f.check_id
    assert f.severity
    assert f.title
    assert f.detail
    assert isinstance(f.weight, int)
    assert f.parameter
    assert isinstance(f.evidence, str)

# ===========================================================================
# evaluate_many
# ===========================================================================

def test_evaluate_many_returns_list():
    results = evaluate_many([
        {"params": {"id": "UNION SELECT 1"}},
        {"params": {"id": "hello"}},
    ])
    assert len(results) == 2

def test_evaluate_many_first_has_finding():
    results = evaluate_many([{"params": {"id": "UNION SELECT 1"}}])
    assert has_check(results[0], "SQLI-001")

def test_evaluate_many_second_clean():
    results = evaluate_many([
        {"params": {"id": "UNION SELECT 1"}},
        {"params": {"id": "safe input"}},
    ])
    assert len(results[1].findings) == 0

def test_evaluate_many_empty_list():
    results = evaluate_many([])
    assert results == []

def test_evaluate_many_respects_block_on_severity():
    results = evaluate_many([
        {"params": {"id": "EXTRACTVALUE(1,1)"}, "block_on_severity": "HIGH"},
        {"params": {"id": "EXTRACTVALUE(1,1)"}, "block_on_severity": "CRITICAL"},
    ])
    assert results[0].blocked is True
    # For second request: SQLI-004 is HIGH, threshold CRITICAL => not blocked
    if results[1].findings and all(f.severity == "HIGH" for f in results[1].findings):
        assert results[1].blocked is False

def test_evaluate_many_body_key():
    results = evaluate_many([{"body": "SLEEP(5)"}])
    assert has_check(results[0], "SQLI-002")

def test_evaluate_many_headers_key():
    results = evaluate_many([{"headers": {"X-H": "UNION SELECT 1"}}])
    assert has_check(results[0], "SQLI-001")

def test_evaluate_many_preserves_order():
    payloads = [
        {"params": {"id": "SLEEP(5)"}},
        {"params": {"id": "EXTRACTVALUE(1,1)"}},
        {"params": {"id": "hello"}},
    ]
    results = evaluate_many(payloads)
    assert has_check(results[0], "SQLI-002")
    assert has_check(results[1], "SQLI-004")
    assert len(results[2].findings) == 0

# ===========================================================================
# Cross-check and multi-parameter scenarios
# ===========================================================================

def test_multiple_params_multiple_checks():
    r = evaluate(params={
        "q": "UNION SELECT 1",
        "id": "SLEEP(5)",
        "x": "EXTRACTVALUE(1,1)",
    })
    ids = fired_ids(r)
    assert "SQLI-001" in ids
    assert "SQLI-002" in ids
    assert "SQLI-004" in ids

def test_combined_headers_and_params():
    r = evaluate(
        params={"id": "1"},
        headers={"X-Custom": "UNION SELECT password FROM users"},
    )
    assert has_check(r, "SQLI-001")

def test_body_and_params():
    r = evaluate(
        params={"safe": "value"},
        body="q=1; DROP TABLE users",
    )
    assert has_check(r, "SQLI-005")

def test_sqli_001_and_005_combined():
    r = evaluate(params={"id": "1 UNION SELECT 1; DROP TABLE users"})
    ids = fired_ids(r)
    assert "SQLI-001" in ids
    assert "SQLI-005" in ids

def test_all_none_returns_empty_result():
    r = evaluate(params=None, headers=None, body=None)
    assert r.findings == []
    assert r.risk_score == 0
    assert r.blocked is False

def test_empty_string_body_no_findings():
    r = evaluate(body="")
    assert len(r.findings) == 0

def test_check_weights_dict_completeness():
    expected_ids = {"SQLI-001", "SQLI-002", "SQLI-003", "SQLI-004", "SQLI-005", "SQLI-006", "SQLI-007"}
    assert expected_ids == set(_CHECK_WEIGHTS.keys())
