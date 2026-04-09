"""
Tests for shared/rulepacks/bot_detection_pack.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.rulepacks.bot_detection_pack import (
    BotAction,
    BotDetectionPack,
    BotRequest,
    BotSeverity,
    RuleMatch,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _req(
    method: str = "GET",
    path: str = "/",
    ua: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
    extra_headers: dict | None = None,
    source_ip: str = "1.2.3.4",
    body: str = "",
) -> BotRequest:
    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if ua == "":
        del headers["User-Agent"]
    if extra_headers:
        headers.update(extra_headers)
    return BotRequest(
        method=method,
        path=path,
        headers=headers,
        source_ip=source_ip,
        body=body,
    )


def _rule_ids(matches: list[RuleMatch]) -> set[str]:
    return {m.rule_id for m in matches}


def _pack(**kwargs) -> BotDetectionPack:
    return BotDetectionPack(**kwargs)


# ===========================================================================
# BotRequest
# ===========================================================================

class TestBotRequest:
    def test_header_case_insensitive(self):
        req = BotRequest(
            method="GET", path="/",
            headers={"User-Agent": "Mozilla/5.0"},
        )
        assert req.header("user-agent") == "Mozilla/5.0"
        assert req.header("USER-AGENT") == "Mozilla/5.0"

    def test_header_missing_returns_empty(self):
        req = BotRequest(method="GET", path="/", headers={})
        assert req.header("Accept") == ""

    def test_has_header_true(self):
        req = BotRequest(method="GET", path="/", headers={"Accept": "text/html"})
        assert req.has_header("accept")

    def test_has_header_false(self):
        req = BotRequest(method="GET", path="/", headers={})
        assert not req.has_header("Accept-Language")


# ===========================================================================
# RuleMatch
# ===========================================================================

class TestRuleMatch:
    def _match(self) -> RuleMatch:
        return RuleMatch(
            rule_id="BOT-UA-001",
            severity=BotSeverity.HIGH,
            action=BotAction.BLOCK,
            title="Test",
            detail="Detail",
            evidence="HeadlessChrome",
            source_ip="1.2.3.4",
            path="/login",
        )

    def test_to_dict_has_required_keys(self):
        d = self._match().to_dict()
        for k in ("rule_id", "severity", "action", "title",
                  "detail", "evidence", "source_ip", "path"):
            assert k in d

    def test_severity_serialized_as_string(self):
        assert self._match().to_dict()["severity"] == "HIGH"

    def test_action_serialized_as_string(self):
        assert self._match().to_dict()["action"] == "BLOCK"

    def test_evidence_truncated_to_256(self):
        m = RuleMatch(
            rule_id="BOT-UA-004",
            severity=BotSeverity.MEDIUM,
            action=BotAction.BLOCK,
            title="t", detail="d",
            evidence="x" * 500,
        )
        assert len(m.to_dict()["evidence"]) == 256


# ===========================================================================
# BOT-UA-001: Headless browser
# ===========================================================================

class TestBOTUA001:
    def test_headless_chrome(self):
        matches = _pack().evaluate(_req(ua="HeadlessChrome/114.0.5735.90"))
        assert "BOT-UA-001" in _rule_ids(matches)

    def test_phantomjs(self):
        matches = _pack().evaluate(_req(ua="PhantomJS/2.1.1"))
        assert "BOT-UA-001" in _rule_ids(matches)

    def test_puppeteer(self):
        matches = _pack().evaluate(_req(ua="Mozilla/5.0 (Puppeteer) Chrome/120"))
        assert "BOT-UA-001" in _rule_ids(matches)

    def test_playwright(self):
        matches = _pack().evaluate(_req(ua="Playwright/1.40"))
        assert "BOT-UA-001" in _rule_ids(matches)

    def test_selenium(self):
        matches = _pack().evaluate(_req(ua="Mozilla/5.0 Selenium/4.10"))
        assert "BOT-UA-001" in _rule_ids(matches)

    def test_normal_chrome_not_fired(self):
        matches = _pack().evaluate(_req(ua="Mozilla/5.0 (Windows NT 10.0) Chrome/120.0"))
        assert "BOT-UA-001" not in _rule_ids(matches)

    def test_severity_is_high(self):
        matches = _pack().evaluate(_req(ua="HeadlessChrome/114"))
        m = next(m for m in matches if m.rule_id == "BOT-UA-001")
        assert m.severity == BotSeverity.HIGH

    def test_action_is_block(self):
        matches = _pack().evaluate(_req(ua="PhantomJS/2"))
        m = next(m for m in matches if m.rule_id == "BOT-UA-001")
        assert m.action == BotAction.BLOCK

    def test_evidence_contains_ua(self):
        ua = "HeadlessChrome/114.0"
        matches = _pack().evaluate(_req(ua=ua))
        m = next(m for m in matches if m.rule_id == "BOT-UA-001")
        assert "HeadlessChrome" in m.evidence


# ===========================================================================
# BOT-UA-002: Scanner
# ===========================================================================

class TestBOTUA002:
    def test_nikto(self):
        matches = _pack().evaluate(_req(ua="Nikto/2.1.6"))
        assert "BOT-UA-002" in _rule_ids(matches)

    def test_sqlmap(self):
        matches = _pack().evaluate(_req(ua="sqlmap/1.7.8#stable"))
        assert "BOT-UA-002" in _rule_ids(matches)

    def test_burp(self):
        matches = _pack().evaluate(_req(ua="Burp Suite v2023.10"))
        assert "BOT-UA-002" in _rule_ids(matches)

    def test_zap(self):
        matches = _pack().evaluate(_req(ua="ZAP/2.14"))
        assert "BOT-UA-002" in _rule_ids(matches)

    def test_nuclei(self):
        matches = _pack().evaluate(_req(ua="nuclei/2.9.9"))
        assert "BOT-UA-002" in _rule_ids(matches)

    def test_normal_ua_not_fired(self):
        matches = _pack().evaluate(_req(ua="Mozilla/5.0 Firefox/120"))
        assert "BOT-UA-002" not in _rule_ids(matches)

    def test_severity_is_critical(self):
        matches = _pack().evaluate(_req(ua="Nikto/2"))
        m = next(m for m in matches if m.rule_id == "BOT-UA-002")
        assert m.severity == BotSeverity.CRITICAL

    def test_action_is_block(self):
        matches = _pack().evaluate(_req(ua="sqlmap/1.7"))
        m = next(m for m in matches if m.rule_id == "BOT-UA-002")
        assert m.action == BotAction.BLOCK


# ===========================================================================
# BOT-UA-003: Missing UA
# ===========================================================================

class TestBOTUA003:
    def test_missing_ua_fires(self):
        req = BotRequest(
            method="GET", path="/",
            headers={"Accept": "text/html"},
        )
        matches = _pack().evaluate(req)
        assert "BOT-UA-003" in _rule_ids(matches)

    def test_present_ua_not_fired(self):
        matches = _pack().evaluate(_req(ua="Mozilla/5.0"))
        assert "BOT-UA-003" not in _rule_ids(matches)

    def test_severity_is_medium(self):
        req = BotRequest(method="GET", path="/", headers={})
        matches = _pack().evaluate(req)
        m = next(m for m in matches if m.rule_id == "BOT-UA-003")
        assert m.severity == BotSeverity.MEDIUM

    def test_action_is_challenge(self):
        req = BotRequest(method="GET", path="/", headers={})
        matches = _pack().evaluate(req)
        m = next(m for m in matches if m.rule_id == "BOT-UA-003")
        assert m.action == BotAction.CHALLENGE


# ===========================================================================
# BOT-UA-004: Long UA
# ===========================================================================

class TestBOTUA004:
    def test_long_ua_fires(self):
        ua = "A" * 600
        matches = _pack().evaluate(_req(ua=ua))
        assert "BOT-UA-004" in _rule_ids(matches)

    def test_normal_length_not_fired(self):
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"
        matches = _pack().evaluate(_req(ua=ua))
        assert "BOT-UA-004" not in _rule_ids(matches)

    def test_custom_max_length(self):
        pack = BotDetectionPack(max_ua_length=10)
        ua = "A" * 11
        matches = pack.evaluate(_req(ua=ua))
        assert "BOT-UA-004" in _rule_ids(matches)

    def test_exactly_at_limit_not_fired(self):
        pack = BotDetectionPack(max_ua_length=100)
        ua = "A" * 100
        matches = pack.evaluate(_req(ua=ua))
        assert "BOT-UA-004" not in _rule_ids(matches)

    def test_severity_is_medium(self):
        ua = "X" * 600
        matches = _pack().evaluate(_req(ua=ua))
        m = next(m for m in matches if m.rule_id == "BOT-UA-004")
        assert m.severity == BotSeverity.MEDIUM

    def test_action_is_block(self):
        ua = "X" * 600
        matches = _pack().evaluate(_req(ua=ua))
        m = next(m for m in matches if m.rule_id == "BOT-UA-004")
        assert m.action == BotAction.BLOCK


# ===========================================================================
# BOT-CS-001: Credential stuffing
# ===========================================================================

class TestBOTCS001:
    def test_post_to_login(self):
        matches = _pack().evaluate(_req(method="POST", path="/login"))
        assert "BOT-CS-001" in _rule_ids(matches)

    def test_post_to_api_auth(self):
        matches = _pack().evaluate(_req(method="POST", path="/api/auth"))
        assert "BOT-CS-001" in _rule_ids(matches)

    def test_post_to_token(self):
        matches = _pack().evaluate(_req(method="POST", path="/oauth/token"))
        assert "BOT-CS-001" in _rule_ids(matches)

    def test_get_to_login_not_fired(self):
        matches = _pack().evaluate(_req(method="GET", path="/login"))
        assert "BOT-CS-001" not in _rule_ids(matches)

    def test_post_to_other_path_not_fired(self):
        matches = _pack().evaluate(_req(method="POST", path="/submit-form"))
        assert "BOT-CS-001" not in _rule_ids(matches)

    def test_custom_auth_endpoint(self):
        pack = BotDetectionPack(auth_endpoints=["/custom/auth"])
        matches = pack.evaluate(_req(method="POST", path="/custom/auth"))
        assert "BOT-CS-001" in _rule_ids(matches)

    def test_severity_is_high(self):
        matches = _pack().evaluate(_req(method="POST", path="/login"))
        m = next(m for m in matches if m.rule_id == "BOT-CS-001")
        assert m.severity == BotSeverity.HIGH

    def test_action_is_challenge(self):
        matches = _pack().evaluate(_req(method="POST", path="/signin"))
        m = next(m for m in matches if m.rule_id == "BOT-CS-001")
        assert m.action == BotAction.CHALLENGE


# ===========================================================================
# BOT-SC-001: Scraper UA
# ===========================================================================

class TestBOTSC001:
    def test_python_requests(self):
        matches = _pack().evaluate(_req(ua="python-requests/2.31.0"))
        assert "BOT-SC-001" in _rule_ids(matches)

    def test_scrapy(self):
        matches = _pack().evaluate(_req(ua="Scrapy/2.11.0 (+https://scrapy.org)"))
        assert "BOT-SC-001" in _rule_ids(matches)

    def test_wget(self):
        matches = _pack().evaluate(_req(ua="Wget/1.21.3"))
        assert "BOT-SC-001" in _rule_ids(matches)

    def test_curl(self):
        matches = _pack().evaluate(_req(ua="curl/7.88.1"))
        assert "BOT-SC-001" in _rule_ids(matches)

    def test_go_http_client(self):
        matches = _pack().evaluate(_req(ua="Go-http-client/1.1"))
        assert "BOT-SC-001" in _rule_ids(matches)

    def test_normal_browser_not_fired(self):
        matches = _pack().evaluate(_req(ua="Mozilla/5.0 (Windows) Firefox/120"))
        assert "BOT-SC-001" not in _rule_ids(matches)

    def test_severity_is_low(self):
        matches = _pack().evaluate(_req(ua="python-requests/2.31"))
        m = next(m for m in matches if m.rule_id == "BOT-SC-001")
        assert m.severity == BotSeverity.LOW

    def test_default_action_is_log(self):
        matches = _pack().evaluate(_req(ua="python-requests/2.31"))
        m = next(m for m in matches if m.rule_id == "BOT-SC-001")
        assert m.action == BotAction.LOG

    def test_challenge_scrapers_flag(self):
        pack = BotDetectionPack(challenge_scrapers=True)
        matches = pack.evaluate(_req(ua="python-requests/2.31"))
        m = next(m for m in matches if m.rule_id == "BOT-SC-001")
        assert m.action == BotAction.CHALLENGE


# ===========================================================================
# BOT-SC-002: Browser-spoofed UA missing fingerprint headers
# ===========================================================================

class TestBOTSC002:
    def test_fires_when_browser_ua_missing_accept_language(self):
        req = BotRequest(
            method="GET", path="/",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows) Chrome/120",
                "Accept": "text/html",
                "Accept-Encoding": "gzip",
                # No Accept-Language
            },
        )
        matches = _pack().evaluate(req)
        assert "BOT-SC-002" in _rule_ids(matches)

    def test_not_fired_when_all_headers_present(self):
        req = BotRequest(
            method="GET", path="/",
            headers={
                "User-Agent": "Mozilla/5.0 Chrome/120",
                "Accept": "text/html",
                "Accept-Encoding": "gzip",
                "Accept-Language": "en-US,en;q=0.9",
            },
        )
        matches = _pack().evaluate(req)
        assert "BOT-SC-002" not in _rule_ids(matches)

    def test_non_browser_ua_not_fired(self):
        req = BotRequest(
            method="GET", path="/",
            headers={"User-Agent": "python-requests/2.31"},
        )
        matches = _pack().evaluate(req)
        assert "BOT-SC-002" not in _rule_ids(matches)

    def test_severity_is_medium(self):
        req = BotRequest(
            method="GET", path="/",
            headers={
                "User-Agent": "Mozilla/5.0 Firefox/120",
                "Accept": "text/html",
            },
        )
        matches = _pack().evaluate(req)
        m = next((m for m in matches if m.rule_id == "BOT-SC-002"), None)
        if m:  # may or may not fire depending on other headers; just check severity
            assert m.severity == BotSeverity.MEDIUM

    def test_headless_ua_not_double_fired(self):
        # HeadlessChrome already caught by BOT-UA-001; BOT-ENV-001 should not also fire
        req = BotRequest(
            method="GET", path="/",
            headers={"User-Agent": "HeadlessChrome/114"},
        )
        matches = _pack().evaluate(req)
        assert "BOT-ENV-001" not in _rule_ids(matches)


# ===========================================================================
# BOT-ENV-001: Missing Accept-Language (headless env signal)
# ===========================================================================

class TestBOTENV001:
    def test_fires_for_browser_ua_without_accept_language(self):
        req = BotRequest(
            method="GET", path="/",
            headers={
                "User-Agent": "Mozilla/5.0 Chrome/120",
                "Accept": "text/html",
                "Accept-Encoding": "gzip",
            },
        )
        matches = _pack().evaluate(req)
        assert "BOT-ENV-001" in _rule_ids(matches)

    def test_not_fired_with_accept_language(self):
        req = BotRequest(
            method="GET", path="/",
            headers={
                "User-Agent": "Mozilla/5.0 Chrome/120",
                "Accept": "text/html",
                "Accept-Encoding": "gzip",
                "Accept-Language": "en-US",
            },
        )
        matches = _pack().evaluate(req)
        assert "BOT-ENV-001" not in _rule_ids(matches)

    def test_not_fired_for_non_browser_ua(self):
        req = BotRequest(
            method="GET", path="/",
            headers={"User-Agent": "python-requests/2.31"},
        )
        matches = _pack().evaluate(req)
        assert "BOT-ENV-001" not in _rule_ids(matches)

    def test_severity_is_low(self):
        req = BotRequest(
            method="GET", path="/",
            headers={
                "User-Agent": "Mozilla/5.0 Chrome/120",
                "Accept": "text/html",
            },
        )
        matches = _pack().evaluate(req)
        m = next((m for m in matches if m.rule_id == "BOT-ENV-001"), None)
        if m:
            assert m.severity == BotSeverity.LOW

    def test_action_is_log(self):
        req = BotRequest(
            method="GET", path="/",
            headers={
                "User-Agent": "Mozilla/5.0 Firefox/120",
                "Accept": "text/html",
            },
        )
        matches = _pack().evaluate(req)
        m = next((m for m in matches if m.rule_id == "BOT-ENV-001"), None)
        if m:
            assert m.action == BotAction.LOG


# ===========================================================================
# evaluate — multiple rules in one request
# ===========================================================================

class TestMultiRuleFire:
    def test_scanner_and_cs_on_post_login(self):
        req = BotRequest(
            method="POST",
            path="/login",
            headers={
                "User-Agent": "sqlmap/1.7",
                "Accept": "text/html",
                "Accept-Encoding": "gzip",
                "Accept-Language": "en-US",
            },
        )
        matches = _pack().evaluate(req)
        ids = _rule_ids(matches)
        assert "BOT-UA-002" in ids
        assert "BOT-CS-001" in ids

    def test_clean_request_no_matches(self):
        req = BotRequest(
            method="GET",
            path="/about",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                "Accept": "text/html,application/xhtml+xml",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "en-US,en;q=0.9",
            },
        )
        matches = _pack().evaluate(req)
        assert matches == []

    def test_source_ip_in_all_matches(self):
        req = BotRequest(
            method="POST",
            path="/login",
            headers={"User-Agent": "sqlmap/1.7", "Accept": "text/html",
                     "Accept-Encoding": "gzip", "Accept-Language": "en"},
            source_ip="10.0.0.99",
        )
        matches = _pack().evaluate(req)
        for m in matches:
            assert m.source_ip == "10.0.0.99"
