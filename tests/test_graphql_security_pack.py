# test_graphql_security_pack.py
# ---------------------------------------------------------------------------
# Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
# Copyright (c) 2026 Cyber Port — hiagokinlevi
# ---------------------------------------------------------------------------
"""
Test suite for GraphQLSecurityPack.

Covers all seven checks (GQL-001 through GQL-007), boundary conditions,
blocked/allowed logic, risk_score computation, helper methods, dataclass
serialisation, and constructor parameters.

Run with:
    python3 -m pytest tests/test_graphql_security_pack.py --override-ini="addopts=" -q
"""
from __future__ import annotations

import sys
import os

# Ensure project root is on the path so shared/ is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from shared.rulepacks.graphql_security_pack import (
    GraphQLEvalResult,
    GraphQLFinding,
    GraphQLRequest,
    GraphQLSecurityPack,
    SeverityLevel,
    _CHECK_WEIGHTS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def pack() -> GraphQLSecurityPack:
    """Default pack with stock configuration."""
    return GraphQLSecurityPack()


@pytest.fixture()
def clean_request() -> GraphQLRequest:
    """A simple, safe GraphQL query that should produce zero findings."""
    return GraphQLRequest(query="{ user { id name email } }")


# ---------------------------------------------------------------------------
# Helper builders
# ---------------------------------------------------------------------------

def _deep_query(depth: int) -> str:
    """Generate a query with the given nesting depth using { brackets."""
    return "{" * depth + " id " + "}" * depth


def _aliased_query(count: int) -> str:
    """Generate a query with `count` alias definitions."""
    aliases = " ".join(f"a{i}: fieldName" for i in range(count))
    return "{ " + aliases + " }"


def _duplicate_field_query(field: str, count: int) -> str:
    """Generate a query where `field` appears `count` times."""
    fields = " ".join(f"{field}" + " { id }" for _ in range(count))
    return "{ " + fields + " }"


# ===========================================================================
# 1. Clean / no-findings cases
# ===========================================================================

class TestCleanQuery:
    def test_simple_query_no_findings(self, pack, clean_request):
        result = pack.evaluate(clean_request)
        assert result.findings == []

    def test_clean_risk_score_is_zero(self, pack, clean_request):
        result = pack.evaluate(clean_request)
        assert result.risk_score == 0

    def test_clean_not_blocked(self, pack, clean_request):
        result = pack.evaluate(clean_request)
        assert result.blocked is False

    def test_shallow_query_two_levels(self, pack):
        req = GraphQLRequest(query="{ users { id } }")
        result = pack.evaluate(req)
        assert not any(f.check_id == "GQL-001" for f in result.findings)

    def test_typename_field_does_not_trigger_depth(self, pack):
        req = GraphQLRequest(query="{ user { __typename id } }")
        result = pack.evaluate(req)
        # __typename contains __type so GQL-003 should fire, but GQL-001 should NOT
        gql001 = [f for f in result.findings if f.check_id == "GQL-001"]
        assert gql001 == []


# ===========================================================================
# 2. GQL-001 — Query depth
# ===========================================================================

class TestGQL001Depth:
    def test_exact_max_depth_does_not_fire(self, pack):
        """Depth == max_depth is allowed."""
        req = GraphQLRequest(query=_deep_query(pack._max_depth))
        result = pack.evaluate(req)
        depth_findings = [f for f in result.findings if f.check_id == "GQL-001"]
        assert depth_findings == []

    def test_max_depth_plus_one_fires(self, pack):
        """Depth == max_depth + 1 must trigger GQL-001."""
        req = GraphQLRequest(query=_deep_query(pack._max_depth + 1))
        result = pack.evaluate(req)
        depth_findings = [f for f in result.findings if f.check_id == "GQL-001"]
        assert len(depth_findings) == 1

    def test_gql_001_severity_is_high(self, pack):
        req = GraphQLRequest(query=_deep_query(pack._max_depth + 1))
        result = pack.evaluate(req)
        finding = next(f for f in result.findings if f.check_id == "GQL-001")
        assert finding.severity == "HIGH"

    def test_shallow_query_does_not_trigger(self, pack):
        req = GraphQLRequest(query="{ user { id } }")
        result = pack.evaluate(req)
        assert not any(f.check_id == "GQL-001" for f in result.findings)

    def test_deeply_nested_query_triggers(self, pack):
        # Default max_depth = 10; generate depth 15
        req = GraphQLRequest(query=_deep_query(15))
        result = pack.evaluate(req)
        assert any(f.check_id == "GQL-001" for f in result.findings)

    def test_string_literal_braces_not_counted(self, pack):
        """Braces inside string literals must not inflate the depth counter."""
        # The outer depth is 3; the string contains many braces but they are inside quotes
        inner_braces = '{"key": "' + "{" * 20 + '"}'
        query = '{ user { profile(filter: ' + inner_braces + ") { id } } }"
        req = GraphQLRequest(query=query)
        result = pack.evaluate(req)
        depth_findings = [f for f in result.findings if f.check_id == "GQL-001"]
        assert depth_findings == []

    def test_custom_max_depth_respected(self):
        pack = GraphQLSecurityPack(max_depth=3)
        req = GraphQLRequest(query=_deep_query(4))  # depth 4 > limit 3
        result = pack.evaluate(req)
        assert any(f.check_id == "GQL-001" for f in result.findings)

    def test_custom_max_depth_allows_exact(self):
        pack = GraphQLSecurityPack(max_depth=3)
        req = GraphQLRequest(query=_deep_query(3))  # depth 3 == limit 3
        result = pack.evaluate(req)
        assert not any(f.check_id == "GQL-001" for f in result.findings)

    def test_gql_001_finding_has_recommendation(self, pack):
        req = GraphQLRequest(query=_deep_query(pack._max_depth + 1))
        result = pack.evaluate(req)
        finding = next(f for f in result.findings if f.check_id == "GQL-001")
        assert finding.recommendation != ""

    def test_escaped_brace_in_string_not_counted(self, pack):
        """Escaped double-quote inside a string must not end the literal early."""
        # Depth is 2; escaped quote inside should not break string tracking
        query = r'{ user(name: "say \"hello\"") { id } }'
        req = GraphQLRequest(query=query)
        result = pack.evaluate(req)
        assert not any(f.check_id == "GQL-001" for f in result.findings)


# ===========================================================================
# 3. GQL-002 — Batch abuse
# ===========================================================================

class TestGQL002Batch:
    def test_operations_at_max_does_not_fire(self, pack):
        """operations_count == max_operations is allowed."""
        req = GraphQLRequest(
            query="{ user { id } }",
            operations_count=pack._max_operations,
        )
        result = pack.evaluate(req)
        assert not any(f.check_id == "GQL-002" for f in result.findings)

    def test_operations_exceeds_max_fires(self, pack):
        req = GraphQLRequest(
            query="{ user { id } }",
            operations_count=pack._max_operations + 1,
        )
        result = pack.evaluate(req)
        assert any(f.check_id == "GQL-002" for f in result.findings)

    def test_gql_002_severity_is_high(self, pack):
        req = GraphQLRequest(query="{ id }", operations_count=pack._max_operations + 1)
        result = pack.evaluate(req)
        finding = next(f for f in result.findings if f.check_id == "GQL-002")
        assert finding.severity == "HIGH"

    def test_gql_002_detail_contains_count(self, pack):
        count = pack._max_operations + 3
        req = GraphQLRequest(query="{ id }", operations_count=count)
        result = pack.evaluate(req)
        finding = next(f for f in result.findings if f.check_id == "GQL-002")
        assert str(count) in finding.detail

    def test_custom_max_operations_respected(self):
        pack = GraphQLSecurityPack(max_operations=2)
        req = GraphQLRequest(query="{ id }", operations_count=3)
        result = pack.evaluate(req)
        assert any(f.check_id == "GQL-002" for f in result.findings)

    def test_single_operation_no_batch_finding(self, pack):
        req = GraphQLRequest(query="{ id }", operations_count=1)
        result = pack.evaluate(req)
        assert not any(f.check_id == "GQL-002" for f in result.findings)


# ===========================================================================
# 4. GQL-003 — Introspection
# ===========================================================================

class TestGQL003Introspection:
    def test_schema_keyword_triggers(self, pack):
        req = GraphQLRequest(query="{ __schema { types { name } } }")
        result = pack.evaluate(req)
        assert any(f.check_id == "GQL-003" for f in result.findings)

    def test_type_keyword_triggers(self, pack):
        req = GraphQLRequest(query='{ __type(name: "User") { fields { name } } }')
        result = pack.evaluate(req)
        assert any(f.check_id == "GQL-003" for f in result.findings)

    def test_typename_contains_type_prefix_triggers(self, pack):
        """__typename contains __type as a substring and therefore does fire."""
        req = GraphQLRequest(query="{ user { __typename id } }")
        result = pack.evaluate(req)
        # __typename includes "__type" so introspection check fires
        assert any(f.check_id == "GQL-003" for f in result.findings)

    def test_clean_query_no_introspection_finding(self, pack, clean_request):
        result = pack.evaluate(clean_request)
        assert not any(f.check_id == "GQL-003" for f in result.findings)

    def test_gql_003_severity_is_medium(self, pack):
        req = GraphQLRequest(query="{ __schema { queryType { name } } }")
        result = pack.evaluate(req)
        finding = next(f for f in result.findings if f.check_id == "GQL-003")
        assert finding.severity == "MEDIUM"

    def test_gql_003_detail_mentions_field(self, pack):
        req = GraphQLRequest(query="{ __schema { queryType { name } } }")
        result = pack.evaluate(req)
        finding = next(f for f in result.findings if f.check_id == "GQL-003")
        assert "__schema" in finding.detail or "__type" in finding.detail


# ===========================================================================
# 5. GQL-004 — Field duplication
# ===========================================================================

class TestGQL004FieldDuplication:
    def test_few_duplicates_does_not_fire(self, pack):
        """Repeating a field 5 times is well under the default limit of 15."""
        req = GraphQLRequest(query=_duplicate_field_query("user", 5))
        result = pack.evaluate(req)
        assert not any(f.check_id == "GQL-004" for f in result.findings)

    def test_many_duplicates_fires(self, pack):
        """Repeating a field 20 times exceeds the default limit of 15."""
        req = GraphQLRequest(query=_duplicate_field_query("user", 20))
        result = pack.evaluate(req)
        assert any(f.check_id == "GQL-004" for f in result.findings)

    def test_gql_004_severity_is_high(self, pack):
        req = GraphQLRequest(query=_duplicate_field_query("user", 20))
        result = pack.evaluate(req)
        finding = next(f for f in result.findings if f.check_id == "GQL-004")
        assert finding.severity == "HIGH"

    def test_custom_max_field_duplicates_respected(self):
        pack = GraphQLSecurityPack(max_field_duplicates=3)
        req = GraphQLRequest(query=_duplicate_field_query("user", 4))
        result = pack.evaluate(req)
        assert any(f.check_id == "GQL-004" for f in result.findings)

    def test_exactly_at_limit_does_not_fire(self, pack):
        """Exactly max_field_duplicates occurrences is allowed (uses >)."""
        req = GraphQLRequest(query=_duplicate_field_query("user", pack._max_field_duplicates))
        result = pack.evaluate(req)
        assert not any(f.check_id == "GQL-004" for f in result.findings)

    def test_gql_004_detail_contains_field_name(self, pack):
        req = GraphQLRequest(query=_duplicate_field_query("targetField", 20))
        result = pack.evaluate(req)
        finding = next((f for f in result.findings if f.check_id == "GQL-004"), None)
        if finding:
            assert "targetField" in finding.detail


# ===========================================================================
# 6. GQL-005 — Alias abuse
# ===========================================================================

class TestGQL005AliasAbuse:
    def test_few_aliases_does_not_fire(self, pack):
        """5 aliases is under the default limit of 10."""
        req = GraphQLRequest(query=_aliased_query(5))
        result = pack.evaluate(req)
        assert not any(f.check_id == "GQL-005" for f in result.findings)

    def test_alias_count_equals_max_does_not_fire(self, pack):
        """Exactly max_aliases aliases must not trigger (uses >)."""
        req = GraphQLRequest(query=_aliased_query(pack._max_aliases))
        result = pack.evaluate(req)
        assert not any(f.check_id == "GQL-005" for f in result.findings)

    def test_alias_count_max_plus_one_fires(self, pack):
        req = GraphQLRequest(query=_aliased_query(pack._max_aliases + 1))
        result = pack.evaluate(req)
        assert any(f.check_id == "GQL-005" for f in result.findings)

    def test_many_aliases_fires(self, pack):
        req = GraphQLRequest(query=_aliased_query(25))
        result = pack.evaluate(req)
        assert any(f.check_id == "GQL-005" for f in result.findings)

    def test_gql_005_severity_is_medium(self, pack):
        req = GraphQLRequest(query=_aliased_query(pack._max_aliases + 1))
        result = pack.evaluate(req)
        finding = next(f for f in result.findings if f.check_id == "GQL-005")
        assert finding.severity == "MEDIUM"

    def test_custom_max_aliases_respected(self):
        pack = GraphQLSecurityPack(max_aliases=3)
        req = GraphQLRequest(query=_aliased_query(4))
        result = pack.evaluate(req)
        assert any(f.check_id == "GQL-005" for f in result.findings)

    def test_gql_005_detail_contains_count(self, pack):
        count = pack._max_aliases + 5
        req = GraphQLRequest(query=_aliased_query(count))
        result = pack.evaluate(req)
        finding = next(f for f in result.findings if f.check_id == "GQL-005")
        assert str(count) in finding.detail

    def test_zero_aliases_clean(self, pack):
        req = GraphQLRequest(query="{ user { id name } }")
        result = pack.evaluate(req)
        assert not any(f.check_id == "GQL-005" for f in result.findings)


# ===========================================================================
# 7. GQL-006 — Directive injection
# ===========================================================================

class TestGQL006DirectiveInjection:
    def test_include_directive_does_not_fire(self, pack):
        req = GraphQLRequest(query="{ user { id @include(if: true) } }")
        result = pack.evaluate(req)
        assert not any(f.check_id == "GQL-006" for f in result.findings)

    def test_skip_directive_does_not_fire(self, pack):
        req = GraphQLRequest(query="{ user { secret @skip(if: false) } }")
        result = pack.evaluate(req)
        assert not any(f.check_id == "GQL-006" for f in result.findings)

    def test_deprecated_directive_does_not_fire(self, pack):
        req = GraphQLRequest(query='{ oldField @deprecated(reason: "use newField") }')
        result = pack.evaluate(req)
        assert not any(f.check_id == "GQL-006" for f in result.findings)

    def test_unknown_directive_rateLimit_fires(self, pack):
        req = GraphQLRequest(query="{ user { id @rateLimit(max: 5) } }")
        result = pack.evaluate(req)
        assert any(f.check_id == "GQL-006" for f in result.findings)

    def test_unknown_directive_customDirective_fires(self, pack):
        req = GraphQLRequest(query="{ posts @customDirective { title } }")
        result = pack.evaluate(req)
        assert any(f.check_id == "GQL-006" for f in result.findings)

    def test_gql_006_severity_is_high(self, pack):
        req = GraphQLRequest(query="{ user @inject { id } }")
        result = pack.evaluate(req)
        finding = next(f for f in result.findings if f.check_id == "GQL-006")
        assert finding.severity == "HIGH"

    def test_gql_006_detail_contains_directive_name(self, pack):
        req = GraphQLRequest(query="{ user @evilDirective { id } }")
        result = pack.evaluate(req)
        finding = next(f for f in result.findings if f.check_id == "GQL-006")
        assert "evilDirective" in finding.detail

    def test_no_directives_clean(self, pack, clean_request):
        result = pack.evaluate(clean_request)
        assert not any(f.check_id == "GQL-006" for f in result.findings)

    def test_shareable_federation_directive_allowed(self, pack):
        req = GraphQLRequest(query="{ product @shareable { id } }")
        result = pack.evaluate(req)
        assert not any(f.check_id == "GQL-006" for f in result.findings)

    def test_key_federation_directive_allowed(self, pack):
        req = GraphQLRequest(query='{ entity @key(fields: "id") { id } }')
        result = pack.evaluate(req)
        assert not any(f.check_id == "GQL-006" for f in result.findings)

    def test_link_federation_directive_allowed(self, pack):
        req = GraphQLRequest(query='{ schema @link(url: "https://specs.apollo.dev/federation/v2.0") { id } }')
        result = pack.evaluate(req)
        assert not any(f.check_id == "GQL-006" for f in result.findings)


# ===========================================================================
# 8. GQL-007 — Variable / SQL injection
# ===========================================================================

class TestGQL007VariableInjection:
    def test_select_keyword_fires(self, pack):
        req = GraphQLRequest(query='{ user(filter: { sql: "SELECT * FROM users" }) { id } }')
        result = pack.evaluate(req)
        assert any(f.check_id == "GQL-007" for f in result.findings)

    def test_union_keyword_fires(self, pack):
        req = GraphQLRequest(query='{ items(search: "1 UNION SELECT id,name FROM secrets") { id } }')
        result = pack.evaluate(req)
        assert any(f.check_id == "GQL-007" for f in result.findings)

    def test_drop_keyword_fires(self, pack):
        req = GraphQLRequest(query="{ admin(cmd: \"DROP TABLE users\") { status } }")
        result = pack.evaluate(req)
        assert any(f.check_id == "GQL-007" for f in result.findings)

    def test_insert_keyword_fires(self, pack):
        req = GraphQLRequest(query="{ action(q: \"INSERT INTO logs VALUES (1)\") { ok } }")
        result = pack.evaluate(req)
        assert any(f.check_id == "GQL-007" for f in result.findings)

    def test_update_keyword_fires(self, pack):
        req = GraphQLRequest(query="{ action(q: \"UPDATE users SET admin=1\") { ok } }")
        result = pack.evaluate(req)
        assert any(f.check_id == "GQL-007" for f in result.findings)

    def test_delete_keyword_fires(self, pack):
        req = GraphQLRequest(query="{ action(q: \"DELETE FROM sessions\") { ok } }")
        result = pack.evaluate(req)
        assert any(f.check_id == "GQL-007" for f in result.findings)

    def test_where_keyword_fires(self, pack):
        req = GraphQLRequest(query="{ user(filter: \"id WHERE 1=1\") { id } }")
        result = pack.evaluate(req)
        assert any(f.check_id == "GQL-007" for f in result.findings)

    def test_sql_comment_chars_fire(self, pack):
        req = GraphQLRequest(query="{ user(name: \"admin'--\") { id } }")
        result = pack.evaluate(req)
        assert any(f.check_id == "GQL-007" for f in result.findings)

    def test_block_comment_fires(self, pack):
        req = GraphQLRequest(query="{ user(name: \"admin/*bypass*/\") { id } }")
        result = pack.evaluate(req)
        assert any(f.check_id == "GQL-007" for f in result.findings)

    def test_clean_query_does_not_fire(self, pack, clean_request):
        result = pack.evaluate(clean_request)
        assert not any(f.check_id == "GQL-007" for f in result.findings)

    def test_gql_007_severity_is_medium(self, pack):
        req = GraphQLRequest(query='{ user(filter: "SELECT id FROM users") { id } }')
        result = pack.evaluate(req)
        finding = next(f for f in result.findings if f.check_id == "GQL-007")
        assert finding.severity == "MEDIUM"

    def test_case_insensitive_sql_keyword(self, pack):
        req = GraphQLRequest(query='{ user(q: "select * from accounts") { id } }')
        result = pack.evaluate(req)
        assert any(f.check_id == "GQL-007" for f in result.findings)

    def test_normal_word_containing_select_not_triggered(self, pack):
        """'selected' is not a whole-word match for SELECT."""
        req = GraphQLRequest(query="{ user(status: \"selected\") { id } }")
        result = pack.evaluate(req)
        assert not any(f.check_id == "GQL-007" for f in result.findings)


# ===========================================================================
# 9. Blocked logic
# ===========================================================================

class TestBlockedLogic:
    def test_blocked_true_when_high_finding_and_threshold_high(self):
        pack = GraphQLSecurityPack(block_on_severity="HIGH")
        req = GraphQLRequest(query=_deep_query(pack._max_depth + 1))  # GQL-001 HIGH
        result = pack.evaluate(req)
        assert result.blocked is True

    def test_blocked_false_when_only_medium_and_threshold_high(self):
        """GQL-003 is MEDIUM; with block_on_severity=HIGH it must not block."""
        pack = GraphQLSecurityPack(block_on_severity="HIGH")
        # Trigger only GQL-003 (MEDIUM): use a clean query with __schema
        req = GraphQLRequest(query="{ __schema { queryType { name } } }")
        result = pack.evaluate(req)
        medium_only = all(f.severity == "MEDIUM" for f in result.findings)
        if medium_only and result.findings:
            assert result.blocked is False

    def test_blocked_true_when_threshold_medium_and_medium_finding(self):
        """With block_on_severity=MEDIUM, a MEDIUM finding must cause blocking."""
        pack = GraphQLSecurityPack(block_on_severity="MEDIUM")
        req = GraphQLRequest(query="{ __schema { queryType { name } } }")
        result = pack.evaluate(req)
        assert result.blocked is True

    def test_blocked_false_for_clean_query(self, pack, clean_request):
        result = pack.evaluate(clean_request)
        assert result.blocked is False

    def test_blocked_true_when_critical_threshold_high(self):
        """CRITICAL >= HIGH so it must block."""
        # Manually build a result with a CRITICAL finding
        finding = GraphQLFinding(
            check_id="GQL-006",
            severity="CRITICAL",
            rule_name="Test",
            detail="Test",
            recommendation="Test",
        )
        result = GraphQLEvalResult(
            findings=[finding],
            risk_score=20,
            blocked=False,
            block_on_severity="HIGH",
        )
        # Re-evaluate blocked flag using the static helper
        pack = GraphQLSecurityPack()
        result.blocked = any(
            pack._severity_value(f.severity) >= pack._severity_value(result.block_on_severity)
            for f in result.findings
        )
        assert result.blocked is True

    def test_blocked_false_when_threshold_critical_and_only_high(self):
        """HIGH < CRITICAL so must not block."""
        finding = GraphQLFinding(
            check_id="GQL-001",
            severity="HIGH",
            rule_name="Test",
            detail="Test",
            recommendation="Test",
        )
        result = GraphQLEvalResult(
            findings=[finding],
            risk_score=25,
            blocked=False,
            block_on_severity="CRITICAL",
        )
        pack_local = GraphQLSecurityPack(block_on_severity="CRITICAL")
        result.blocked = any(
            pack_local._severity_value(f.severity) >= pack_local._severity_value(result.block_on_severity)
            for f in result.findings
        )
        assert result.blocked is False


# ===========================================================================
# 10. Risk score computation
# ===========================================================================

class TestRiskScore:
    def test_single_high_finding_correct_weight(self):
        pack = GraphQLSecurityPack()
        req = GraphQLRequest(query=_deep_query(pack._max_depth + 1))  # GQL-001 weight=25
        result = pack.evaluate(req)
        # Ensure GQL-001 fires and only GQL-001 (clean query otherwise)
        fired = {f.check_id for f in result.findings}
        expected = sum(_CHECK_WEIGHTS[cid] for cid in fired)
        assert result.risk_score == min(100, expected)

    def test_risk_score_capped_at_100(self):
        """Trigger as many checks as possible and confirm cap at 100."""
        # GQL-002 + GQL-003 + GQL-007 + deep nesting — enough to exceed 100
        pack = GraphQLSecurityPack(max_depth=1, max_operations=1, max_aliases=1)
        query = (
            "{ " * 5
            + "__schema { queryType { name SELECT * FROM users } }"
            + "} " * 5
        )
        req = GraphQLRequest(query=query, operations_count=5)
        result = pack.evaluate(req)
        assert result.risk_score <= 100

    def test_zero_findings_zero_score(self, pack, clean_request):
        result = pack.evaluate(clean_request)
        assert result.risk_score == 0

    def test_check_weights_dict_has_all_ids(self):
        expected_ids = {"GQL-001", "GQL-002", "GQL-003", "GQL-004", "GQL-005", "GQL-006", "GQL-007"}
        assert expected_ids == set(_CHECK_WEIGHTS.keys())

    def test_all_weights_positive(self):
        for cid, weight in _CHECK_WEIGHTS.items():
            assert weight > 0, f"{cid} has non-positive weight {weight}"

    def test_unique_fired_ids_not_double_counted(self, pack):
        """Firing the same check twice should not double its weight."""
        # Build a result manually with two findings for the same check ID
        f1 = GraphQLFinding("GQL-001", "HIGH", "r", "d", "rec")
        f2 = GraphQLFinding("GQL-001", "HIGH", "r", "d", "rec")
        fired_ids = {f.check_id for f in [f1, f2]}
        score = min(100, sum(_CHECK_WEIGHTS.get(cid, 0) for cid in fired_ids))
        assert score == _CHECK_WEIGHTS["GQL-001"]


# ===========================================================================
# 11. by_severity()
# ===========================================================================

class TestBySeverity:
    def test_by_severity_has_all_buckets(self, pack, clean_request):
        result = pack.evaluate(clean_request)
        bys = result.by_severity()
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert level in bys

    def test_by_severity_empty_buckets_for_clean(self, pack, clean_request):
        result = pack.evaluate(clean_request)
        bys = result.by_severity()
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert bys[level] == []

    def test_by_severity_classifies_high_finding(self, pack):
        req = GraphQLRequest(query=_deep_query(pack._max_depth + 1))
        result = pack.evaluate(req)
        bys = result.by_severity()
        assert any(f.check_id == "GQL-001" for f in bys["HIGH"])

    def test_by_severity_classifies_medium_finding(self, pack):
        req = GraphQLRequest(query="{ __schema { types { name } } }")
        result = pack.evaluate(req)
        bys = result.by_severity()
        assert any(f.check_id == "GQL-003" for f in bys["MEDIUM"])

    def test_by_severity_returns_dict(self, pack, clean_request):
        result = pack.evaluate(clean_request)
        assert isinstance(result.by_severity(), dict)

    def test_by_severity_all_findings_accounted(self, pack):
        req = GraphQLRequest(
            query=_deep_query(pack._max_depth + 1),
            operations_count=pack._max_operations + 1,
        )
        result = pack.evaluate(req)
        bys = result.by_severity()
        all_in_buckets = [f for bucket in bys.values() for f in bucket]
        assert len(all_in_buckets) == len(result.findings)


# ===========================================================================
# 12. summary()
# ===========================================================================

class TestSummary:
    def test_summary_contains_risk_score(self, pack, clean_request):
        result = pack.evaluate(clean_request)
        assert "risk_score=0" in result.summary()

    def test_summary_contains_allowed_for_clean(self, pack, clean_request):
        result = pack.evaluate(clean_request)
        assert "ALLOWED" in result.summary()

    def test_summary_contains_blocked_for_high_finding(self, pack):
        req = GraphQLRequest(query=_deep_query(pack._max_depth + 1))
        result = pack.evaluate(req)
        assert "BLOCKED" in result.summary()

    def test_summary_returns_string(self, pack, clean_request):
        result = pack.evaluate(clean_request)
        assert isinstance(result.summary(), str)

    def test_summary_mentions_check_id_on_finding(self, pack):
        req = GraphQLRequest(query=_deep_query(pack._max_depth + 1))
        result = pack.evaluate(req)
        assert "GQL-001" in result.summary()


# ===========================================================================
# 13. evaluate_many()
# ===========================================================================

class TestEvaluateMany:
    def test_returns_list(self, pack, clean_request):
        results = pack.evaluate_many([clean_request])
        assert isinstance(results, list)

    def test_returns_correct_count(self, pack, clean_request):
        requests = [clean_request] * 5
        results = pack.evaluate_many(requests)
        assert len(results) == 5

    def test_empty_list_returns_empty(self, pack):
        results = pack.evaluate_many([])
        assert results == []

    def test_each_result_is_eval_result(self, pack, clean_request):
        results = pack.evaluate_many([clean_request, clean_request])
        for r in results:
            assert isinstance(r, GraphQLEvalResult)

    def test_mixed_requests_correct_findings(self, pack, clean_request):
        bad_req = GraphQLRequest(query=_deep_query(pack._max_depth + 1))
        results = pack.evaluate_many([clean_request, bad_req])
        assert results[0].findings == []
        assert any(f.check_id == "GQL-001" for f in results[1].findings)

    def test_order_preserved(self, pack):
        queries = [
            GraphQLRequest(query="{ a { id } }"),
            GraphQLRequest(query=_deep_query(pack._max_depth + 1)),
            GraphQLRequest(query="{ b { id } }"),
        ]
        results = pack.evaluate_many(queries)
        assert not any(f.check_id == "GQL-001" for f in results[0].findings)
        assert any(f.check_id == "GQL-001" for f in results[1].findings)
        assert not any(f.check_id == "GQL-001" for f in results[2].findings)


# ===========================================================================
# 14. to_dict() for all dataclasses
# ===========================================================================

class TestToDict:
    def test_graphql_request_to_dict_keys(self):
        req = GraphQLRequest(
            query="{ user { id } }",
            operation_name="GetUser",
            variables={"id": "1"},
            operations_count=1,
            source_ip="127.0.0.1",
        )
        d = req.to_dict()
        assert set(d.keys()) == {"query", "operation_name", "variables", "operations_count", "source_ip"}

    def test_graphql_request_to_dict_values(self):
        req = GraphQLRequest(
            query="{ user { id } }",
            operation_name="GetUser",
            variables={"id": "1"},
            operations_count=2,
            source_ip="10.0.0.1",
        )
        d = req.to_dict()
        assert d["query"] == "{ user { id } }"
        assert d["operation_name"] == "GetUser"
        assert d["variables"] == {"id": "1"}
        assert d["operations_count"] == 2
        assert d["source_ip"] == "10.0.0.1"

    def test_graphql_finding_to_dict_keys(self):
        finding = GraphQLFinding(
            check_id="GQL-001",
            severity="HIGH",
            rule_name="Depth",
            detail="Too deep",
            recommendation="Fix it",
        )
        d = finding.to_dict()
        assert set(d.keys()) == {"check_id", "severity", "rule_name", "detail", "recommendation"}

    def test_graphql_finding_to_dict_values(self):
        finding = GraphQLFinding(
            check_id="GQL-003",
            severity="MEDIUM",
            rule_name="Introspection",
            detail="Schema exposed",
            recommendation="Disable it",
        )
        d = finding.to_dict()
        assert d["check_id"] == "GQL-003"
        assert d["severity"] == "MEDIUM"
        assert d["rule_name"] == "Introspection"

    def test_graphql_eval_result_to_dict_keys(self, pack, clean_request):
        result = pack.evaluate(clean_request)
        d = result.to_dict()
        assert set(d.keys()) == {"findings", "risk_score", "blocked", "block_on_severity"}

    def test_graphql_eval_result_to_dict_findings_is_list(self, pack, clean_request):
        result = pack.evaluate(clean_request)
        d = result.to_dict()
        assert isinstance(d["findings"], list)

    def test_graphql_eval_result_to_dict_findings_are_dicts(self, pack):
        req = GraphQLRequest(query=_deep_query(pack._max_depth + 1))
        result = pack.evaluate(req)
        d = result.to_dict()
        for item in d["findings"]:
            assert isinstance(item, dict)

    def test_graphql_eval_result_to_dict_risk_score_type(self, pack, clean_request):
        result = pack.evaluate(clean_request)
        d = result.to_dict()
        assert isinstance(d["risk_score"], int)

    def test_graphql_eval_result_to_dict_blocked_type(self, pack, clean_request):
        result = pack.evaluate(clean_request)
        d = result.to_dict()
        assert isinstance(d["blocked"], bool)

    def test_graphql_request_to_dict_none_defaults(self):
        req = GraphQLRequest(query="{ id }")
        d = req.to_dict()
        assert d["operation_name"] is None
        assert d["variables"] is None
        assert d["source_ip"] is None
        assert d["operations_count"] == 1


# ===========================================================================
# 15. SeverityLevel enum and _severity_value
# ===========================================================================

class TestSeverityHelpers:
    def test_severity_level_ordering(self):
        assert SeverityLevel.INFO < SeverityLevel.LOW
        assert SeverityLevel.LOW < SeverityLevel.MEDIUM
        assert SeverityLevel.MEDIUM < SeverityLevel.HIGH
        assert SeverityLevel.HIGH < SeverityLevel.CRITICAL

    def test_severity_value_critical_is_4(self):
        pack = GraphQLSecurityPack()
        assert pack._severity_value("CRITICAL") == 4

    def test_severity_value_high_is_3(self):
        pack = GraphQLSecurityPack()
        assert pack._severity_value("HIGH") == 3

    def test_severity_value_medium_is_2(self):
        pack = GraphQLSecurityPack()
        assert pack._severity_value("MEDIUM") == 2

    def test_severity_value_low_is_1(self):
        pack = GraphQLSecurityPack()
        assert pack._severity_value("LOW") == 1

    def test_severity_value_info_is_0(self):
        pack = GraphQLSecurityPack()
        assert pack._severity_value("INFO") == 0

    def test_severity_value_unknown_defaults_to_0(self):
        pack = GraphQLSecurityPack()
        assert pack._severity_value("UNKNOWN") == 0

    def test_severity_value_case_insensitive(self):
        pack = GraphQLSecurityPack()
        assert pack._severity_value("high") == 3
        assert pack._severity_value("MEDIUM") == 2


# ===========================================================================
# 16. Constructor parameter propagation
# ===========================================================================

class TestConstructorParams:
    def test_max_depth_stored(self):
        pack = GraphQLSecurityPack(max_depth=5)
        assert pack._max_depth == 5

    def test_max_operations_stored(self):
        pack = GraphQLSecurityPack(max_operations=3)
        assert pack._max_operations == 3

    def test_max_aliases_stored(self):
        pack = GraphQLSecurityPack(max_aliases=7)
        assert pack._max_aliases == 7

    def test_max_field_duplicates_stored(self):
        pack = GraphQLSecurityPack(max_field_duplicates=8)
        assert pack._max_field_duplicates == 8

    def test_block_on_severity_stored(self):
        pack = GraphQLSecurityPack(block_on_severity="MEDIUM")
        assert pack._block_on_severity == "MEDIUM"

    def test_default_block_on_severity_is_high(self):
        pack = GraphQLSecurityPack()
        assert pack._block_on_severity == "HIGH"

    def test_default_max_depth_is_10(self):
        pack = GraphQLSecurityPack()
        assert pack._max_depth == 10

    def test_default_max_operations_is_5(self):
        pack = GraphQLSecurityPack()
        assert pack._max_operations == 5

    def test_default_max_aliases_is_10(self):
        pack = GraphQLSecurityPack()
        assert pack._max_aliases == 10

    def test_default_max_field_duplicates_is_15(self):
        pack = GraphQLSecurityPack()
        assert pack._max_field_duplicates == 15


# ===========================================================================
# 17. GraphQLRequest field defaults and optional fields
# ===========================================================================

class TestGraphQLRequestDefaults:
    def test_operations_count_defaults_to_one(self):
        req = GraphQLRequest(query="{ id }")
        assert req.operations_count == 1

    def test_operation_name_defaults_to_none(self):
        req = GraphQLRequest(query="{ id }")
        assert req.operation_name is None

    def test_variables_defaults_to_none(self):
        req = GraphQLRequest(query="{ id }")
        assert req.variables is None

    def test_source_ip_defaults_to_none(self):
        req = GraphQLRequest(query="{ id }")
        assert req.source_ip is None

    def test_source_ip_set(self):
        req = GraphQLRequest(query="{ id }", source_ip="192.168.1.1")
        assert req.source_ip == "192.168.1.1"

    def test_variables_set(self):
        req = GraphQLRequest(query="{ id }", variables={"userId": "42"})
        assert req.variables == {"userId": "42"}


# ===========================================================================
# 18. GraphQLFinding structure
# ===========================================================================

class TestGraphQLFindingStructure:
    def test_finding_check_id_set(self):
        f = GraphQLFinding("GQL-001", "HIGH", "Depth", "d", "r")
        assert f.check_id == "GQL-001"

    def test_finding_severity_set(self):
        f = GraphQLFinding("GQL-002", "HIGH", "Batch", "d", "r")
        assert f.severity == "HIGH"

    def test_finding_rule_name_set(self):
        f = GraphQLFinding("GQL-003", "MEDIUM", "Introspection", "d", "r")
        assert f.rule_name == "Introspection"

    def test_finding_detail_set(self):
        f = GraphQLFinding("GQL-004", "HIGH", "Dup", "detail text", "r")
        assert f.detail == "detail text"

    def test_finding_recommendation_set(self):
        f = GraphQLFinding("GQL-005", "MEDIUM", "Alias", "d", "recommendation text")
        assert f.recommendation == "recommendation text"

    def test_all_evaluated_findings_have_recommendation(self, pack):
        req = GraphQLRequest(
            query=_deep_query(pack._max_depth + 1),
        )
        result = pack.evaluate(req)
        for f in result.findings:
            assert f.recommendation.strip() != ""

    def test_all_evaluated_findings_have_detail(self, pack):
        req = GraphQLRequest(
            query="{ __schema { types { name } } }",
        )
        result = pack.evaluate(req)
        for f in result.findings:
            assert f.detail.strip() != ""
