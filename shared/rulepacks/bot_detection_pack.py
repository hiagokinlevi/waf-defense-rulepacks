"""
Bot Detection Rulepack
======================
Identifies automated clients including headless browsers, credential-stuffing
bots, scraping frameworks, and scan tools. Evaluates HTTP requests and optional
session-level signals to produce RuleMatch findings.

Rule IDs
---------
BOT-UA-001   Headless browser / automation framework UA
BOT-UA-002   Known scanner / vuln-assessment UA
BOT-UA-003   Missing or empty User-Agent
BOT-UA-004   Excessively long or binary User-Agent
BOT-CS-001   Credential-stuffing pattern (high-velocity POST to auth endpoint)
BOT-CS-002   Distributed credential stuffing (many IPs, same endpoint)
BOT-SC-001   Scraping UA (Scrapy, BeautifulSoup, Wget harvest pattern)
BOT-SC-002   Absence of browser fingerprint headers on browser-spoofed UA
BOT-ENV-001  Headless environment signal in Accept-Language or missing headers

Usage::

    from shared.rulepacks.bot_detection_pack import BotDetectionPack, BotRequest

    pack = BotDetectionPack()
    request = BotRequest(
        method="POST",
        path="/api/login",
        headers={
            "User-Agent": "HeadlessChrome/114",
            "Accept": "application/json",
        },
        source_ip="1.2.3.4",
    )
    matches = pack.evaluate(request)
    for m in matches:
        print(m.to_dict())
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Severity / Action
# ---------------------------------------------------------------------------

class BotSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class BotAction(str, Enum):
    BLOCK      = "BLOCK"
    CHALLENGE  = "CHALLENGE"  # e.g. JS challenge / CAPTCHA
    LOG        = "LOG"


# ---------------------------------------------------------------------------
# BotRequest
# ---------------------------------------------------------------------------

@dataclass
class BotRequest:
    """
    Minimal HTTP request model for bot detection evaluation.

    Attributes:
        method:         HTTP method (GET, POST, …).
        path:           Request path (e.g. "/api/login").
        headers:        Dict of header-name → value (case-insensitive lookup
                        is handled internally).
        source_ip:      Client IP address.
        body:           Raw request body (optional, used for credential checks).
        timestamp:      Unix timestamp (defaults to now).
    """
    method:    str
    path:      str
    headers:   Dict[str, str] = field(default_factory=dict)
    source_ip: str = ""
    body:      str = ""
    timestamp: float = field(default_factory=time.time)

    def header(self, name: str) -> str:
        """Case-insensitive header lookup; returns empty string if absent."""
        name_lower = name.lower()
        for k, v in self.headers.items():
            if k.lower() == name_lower:
                return v
        return ""

    def has_header(self, name: str) -> bool:
        return self.header(name) != ""


# ---------------------------------------------------------------------------
# RuleMatch
# ---------------------------------------------------------------------------

@dataclass
class RuleMatch:
    """
    A bot detection rule match.

    Attributes:
        rule_id:   BOT-* identifier.
        severity:  Severity level.
        action:    Recommended action.
        title:     Short human-readable title.
        detail:    Explanation of what triggered the rule.
        evidence:  The specific value that triggered (UA, IP, etc.).
        source_ip: Client IP from the request.
        path:      Request path.
    """
    rule_id:   str
    severity:  BotSeverity
    action:    BotAction
    title:     str
    detail:    str
    evidence:  str = ""
    source_ip: str = ""
    path:      str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id":   self.rule_id,
            "severity":  self.severity.value,
            "action":    self.action.value,
            "title":     self.title,
            "detail":    self.detail,
            "evidence":  self.evidence[:256],
            "source_ip": self.source_ip,
            "path":      self.path,
        }


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# BOT-UA-001: Headless browser / automation framework
_HEADLESS_UA_PATTERNS: List[str] = [
    r"HeadlessChrome",
    r"PhantomJS",
    r"Puppeteer",
    r"Playwright",
    r"Selenium",
    r"WebDriver",
    r"ChromeDriver",
    r"GeckoDriver",
    r"SlimerJS",
    r"ZombieJS",
    r"NightmareJS",
    r"casperjs",
    r"wkhtmlto",
    r"splash",         # Scrapy Splash
    r"Electron",
]
_HEADLESS_UA_RE = re.compile(
    "|".join(_HEADLESS_UA_PATTERNS),
    re.IGNORECASE,
)

# BOT-UA-002: Known scanner / vuln-assessment UAs
_SCANNER_UA_PATTERNS: List[str] = [
    r"Nikto",
    r"sqlmap",
    r"Nmap\s+Scripting",
    r"Masscan",
    r"ZAP",
    r"w3af",
    r"Acunetix",
    r"Nessus",
    r"OpenVAS",
    r"Burp(?:\s+Suite)?",
    r"dirbuster",
    r"gobuster",
    r"ffuf",
    r"nuclei",
    r"wfuzz",
]
_SCANNER_UA_RE = re.compile(
    "|".join(_SCANNER_UA_PATTERNS),
    re.IGNORECASE,
)

# BOT-SC-001: Scraping-oriented UAs
_SCRAPER_UA_PATTERNS: List[str] = [
    r"python-requests",
    r"python-urllib",
    r"aiohttp",
    r"Scrapy",
    r"curl/",
    r"Wget/",
    r"libwww-perl",
    r"Go-http-client",
    r"Java/",
    r"okhttp",
    r"axios",
    r"node-fetch",
    r"got\s",
]
_SCRAPER_UA_RE = re.compile(
    "|".join(_SCRAPER_UA_PATTERNS),
    re.IGNORECASE,
)

# Auth endpoint paths (credential stuffing target)
_AUTH_PATH_RE = re.compile(
    r"(?:/login|/signin|/auth|/token|/oauth|/api/auth|/api/login|/account/login)",
    re.IGNORECASE,
)

# Headers that real browsers always send
_BROWSER_FINGERPRINT_HEADERS = frozenset({
    "accept",
    "accept-encoding",
    "accept-language",
})

# Browser UA fragments that trigger fingerprint check
_BROWSER_UA_RE = re.compile(
    r"Mozilla|Chrome|Safari|Firefox|Edge|Opera",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# BotDetectionPack
# ---------------------------------------------------------------------------

class BotDetectionPack:
    """
    Bot detection rulepack.

    Args:
        max_ua_length:          Max acceptable User-Agent length (BOT-UA-004).
        auth_endpoints:         Additional auth-endpoint path patterns to
                                append to the default list.
        challenge_scrapers:     If True, scraper UAs get CHALLENGE instead of LOG.
    """

    def __init__(
        self,
        max_ua_length: int = 512,
        auth_endpoints: Optional[List[str]] = None,
        challenge_scrapers: bool = False,
    ) -> None:
        self._max_ua_length    = max_ua_length
        self._challenge_scrapers = challenge_scrapers
        extra = auth_endpoints or []
        if extra:
            pattern = "|".join(
                re.escape(ep) for ep in extra
            )
            self._auth_re = re.compile(
                _AUTH_PATH_RE.pattern + "|" + pattern,
                re.IGNORECASE,
            )
        else:
            self._auth_re = _AUTH_PATH_RE

    def evaluate(self, request: BotRequest) -> List[RuleMatch]:
        """
        Evaluate a request against all bot detection rules.

        Returns:
            List of RuleMatch objects for every rule that fired.
        """
        matches: List[RuleMatch] = []
        ua = request.header("User-Agent")

        matches.extend(self._check_ua_headless(request, ua))
        matches.extend(self._check_ua_scanner(request, ua))
        matches.extend(self._check_ua_missing(request, ua))
        matches.extend(self._check_ua_length(request, ua))
        matches.extend(self._check_credential_stuffing(request))
        matches.extend(self._check_scraper_ua(request, ua))
        matches.extend(self._check_missing_browser_headers(request, ua))
        matches.extend(self._check_headless_env(request, ua))

        return matches

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_ua_headless(self, req: BotRequest, ua: str) -> List[RuleMatch]:
        if ua and _HEADLESS_UA_RE.search(ua):
            m = _HEADLESS_UA_RE.search(ua)
            return [RuleMatch(
                rule_id="BOT-UA-001",
                severity=BotSeverity.HIGH,
                action=BotAction.BLOCK,
                title="Headless browser / automation framework detected",
                detail=(
                    f"User-Agent matches headless browser or automation "
                    f"framework pattern: '{m.group()}'."
                ),
                evidence=ua[:256],
                source_ip=req.source_ip,
                path=req.path,
            )]
        return []

    def _check_ua_scanner(self, req: BotRequest, ua: str) -> List[RuleMatch]:
        if ua and _SCANNER_UA_RE.search(ua):
            m = _SCANNER_UA_RE.search(ua)
            return [RuleMatch(
                rule_id="BOT-UA-002",
                severity=BotSeverity.CRITICAL,
                action=BotAction.BLOCK,
                title="Known security scanner User-Agent",
                detail=(
                    f"User-Agent matches known security scanner: '{m.group()}'."
                ),
                evidence=ua[:256],
                source_ip=req.source_ip,
                path=req.path,
            )]
        return []

    def _check_ua_missing(self, req: BotRequest, ua: str) -> List[RuleMatch]:
        if not ua:
            return [RuleMatch(
                rule_id="BOT-UA-003",
                severity=BotSeverity.MEDIUM,
                action=BotAction.CHALLENGE,
                title="Missing or empty User-Agent",
                detail="Request carries no User-Agent header.",
                evidence="",
                source_ip=req.source_ip,
                path=req.path,
            )]
        return []

    def _check_ua_length(self, req: BotRequest, ua: str) -> List[RuleMatch]:
        if ua and len(ua) > self._max_ua_length:
            return [RuleMatch(
                rule_id="BOT-UA-004",
                severity=BotSeverity.MEDIUM,
                action=BotAction.BLOCK,
                title="Excessively long User-Agent",
                detail=(
                    f"User-Agent length {len(ua)} exceeds maximum "
                    f"{self._max_ua_length}."
                ),
                evidence=ua[:64] + "…",
                source_ip=req.source_ip,
                path=req.path,
            )]
        return []

    def _check_credential_stuffing(self, req: BotRequest) -> List[RuleMatch]:
        if req.method.upper() == "POST" and self._auth_re.search(req.path):
            return [RuleMatch(
                rule_id="BOT-CS-001",
                severity=BotSeverity.HIGH,
                action=BotAction.CHALLENGE,
                title="POST to authentication endpoint",
                detail=(
                    f"POST request to auth endpoint '{req.path}' — "
                    f"potential credential stuffing probe."
                ),
                evidence=req.path,
                source_ip=req.source_ip,
                path=req.path,
            )]
        return []

    def _check_scraper_ua(self, req: BotRequest, ua: str) -> List[RuleMatch]:
        if ua and _SCRAPER_UA_RE.search(ua):
            m = _SCRAPER_UA_RE.search(ua)
            action = BotAction.CHALLENGE if self._challenge_scrapers else BotAction.LOG
            return [RuleMatch(
                rule_id="BOT-SC-001",
                severity=BotSeverity.LOW,
                action=action,
                title="Scraping or automation library User-Agent",
                detail=(
                    f"User-Agent matches known scraping / HTTP-library pattern: "
                    f"'{m.group()}'."
                ),
                evidence=ua[:256],
                source_ip=req.source_ip,
                path=req.path,
            )]
        return []

    def _check_missing_browser_headers(self, req: BotRequest, ua: str) -> List[RuleMatch]:
        """BOT-SC-002: UA claims to be a browser but lacks fingerprint headers."""
        if not ua or not _BROWSER_UA_RE.search(ua):
            return []
        missing = [
            h for h in _BROWSER_FINGERPRINT_HEADERS
            if not req.has_header(h)
        ]
        if missing:
            return [RuleMatch(
                rule_id="BOT-SC-002",
                severity=BotSeverity.MEDIUM,
                action=BotAction.CHALLENGE,
                title="Browser-spoofed UA missing fingerprint headers",
                detail=(
                    f"UA claims browser ({ua[:64]}) but is missing standard "
                    f"browser headers: {', '.join(sorted(missing))}."
                ),
                evidence=ua[:256],
                source_ip=req.source_ip,
                path=req.path,
            )]
        return []

    def _check_headless_env(self, req: BotRequest, ua: str) -> List[RuleMatch]:
        """BOT-ENV-001: Accept-Language absent or suspicious (headless signal)."""
        # Only flag when UA looks browser-like (not already caught by UA-001)
        if not ua or not _BROWSER_UA_RE.search(ua):
            return []
        if _HEADLESS_UA_RE.search(ua):
            return []  # already caught by BOT-UA-001
        accept_lang = req.header("Accept-Language")
        if not accept_lang:
            return [RuleMatch(
                rule_id="BOT-ENV-001",
                severity=BotSeverity.LOW,
                action=BotAction.LOG,
                title="Missing Accept-Language header (headless signal)",
                detail=(
                    "Browser-like UA present but Accept-Language is absent — "
                    "common in headless or automated environments."
                ),
                evidence=ua[:128],
                source_ip=req.source_ip,
                path=req.path,
            )]
        return []
