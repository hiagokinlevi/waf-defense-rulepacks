"""
Tests for shared/rulepacks/api_security_pack.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.rulepacks.api_security_pack import (
    Action,
    ApiSecurityRulepack,
    RuleMatch,
    Severity,
    _is_protected_path,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _req(
    method: str = "GET",
    path: str = "/api/v1/users",
    headers: dict | None = None,
    body: str = "",
    params: dict | None = None,
    scheme: str = "https",
    session_count: int = 0,
) -> dict:
    return {
        "method": method,
        "path": path,
        "headers": headers or {},
        "body": body,
        "params": params or {},
        "scheme": scheme,
        "session_request_count": session_count,
    }


def _auth_header(token: str = "Bearer eyJ.test.token") -> dict:
    return {"Authorization": token}


def _pack() -> ApiSecurityRulepack:
    return ApiSecurityRulepack()


def _rule_ids(matches: list[RuleMatch]) -> set[str]:
    return {m.rule_id for m in matches}


# ===========================================================================
# _is_protected_path
# ===========================================================================

class TestIsProtectedPath:
    def test_api_prefix_protected(self):
        assert _is_protected_path("/api/users")

    def test_v1_prefix_protected(self):
        assert _is_protected_path("/v1/items")

    def test_graphql_protected(self):
        assert _is_protected_path("/graphql")

    def test_admin_protected(self):
        assert _is_protected_path("/admin/dashboard")

    def test_non_api_path_not_protected(self):
        assert not _is_protected_path("/public/health")

    def test_exempt_path_not_protected(self):
        assert not _is_protected_path("/api/health")
        assert not _is_protected_path("/api/ping")

    def test_auth_path_exempt(self):
        assert not _is_protected_path("/v1/login")


# ===========================================================================
# RuleMatch
# ===========================================================================

class TestRuleMatch:
    def _m(self) -> RuleMatch:
        return RuleMatch(
            rule_id="API-AUTH-001",
            severity=Severity.HIGH,
            action=Action.BLOCK,
            title="Test",
            detail="Detail",
            matched_on="headers",
            matched_value="<absent>",
        )

    def test_summary_contains_rule_id(self):
        assert "API-AUTH-001" in self._m().summary()

    def test_summary_contains_action(self):
        assert "BLOCK" in self._m().summary()

    def test_to_dict_keys(self):
        d = self._m().to_dict()
        for k in ("rule_id", "severity", "action", "title", "detail",
                  "matched_on", "matched_value"):
            assert k in d

    def test_severity_serialized_as_string(self):
        assert self._m().to_dict()["severity"] == "HIGH"


# ===========================================================================
# API-AUTH-001: Missing auth
# ===========================================================================

class TestAPIAuth001:
    def test_fires_when_no_auth_on_protected_path(self):
        pack = _pack()
        matches = pack.evaluate(_req(path="/api/users"))
        assert "API-AUTH-001" in _rule_ids(matches)

    def test_not_fired_when_bearer_token_present(self):
        pack = _pack()
        matches = pack.evaluate(_req(path="/api/users", headers=_auth_header()))
        assert "API-AUTH-001" not in _rule_ids(matches)

    def test_not_fired_for_options_method(self):
        pack = _pack()
        matches = pack.evaluate(_req(method="OPTIONS", path="/api/users"))
        assert "API-AUTH-001" not in _rule_ids(matches)

    def test_not_fired_for_exempt_path(self):
        pack = _pack()
        matches = pack.evaluate(_req(path="/api/health"))
        assert "API-AUTH-001" not in _rule_ids(matches)

    def test_not_fired_for_non_api_path(self):
        pack = _pack()
        matches = pack.evaluate(_req(path="/index.html"))
        assert "API-AUTH-001" not in _rule_ids(matches)

    def test_session_cookie_satisfies_auth(self):
        pack = _pack()
        matches = pack.evaluate(_req(
            path="/api/users",
            headers={"Cookie": "session=abc123"},
        ))
        assert "API-AUTH-001" not in _rule_ids(matches)

    def test_auth001_is_high_severity(self):
        pack = _pack()
        matches = pack.evaluate(_req(path="/api/users"))
        m = next(m for m in matches if m.rule_id == "API-AUTH-001")
        assert m.severity == Severity.HIGH

    def test_auth001_action_is_block(self):
        pack = _pack()
        matches = pack.evaluate(_req(path="/api/users"))
        m = next(m for m in matches if m.rule_id == "API-AUTH-001")
        assert m.action == Action.BLOCK


# ===========================================================================
# API-AUTH-002: Basic auth over HTTP
# ===========================================================================

class TestAPIAuth002:
    def test_fires_for_basic_over_http(self):
        pack = _pack()
        matches = pack.evaluate(_req(
            path="/api/users",
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
            scheme="http",
        ))
        assert "API-AUTH-002" in _rule_ids(matches)

    def test_not_fired_over_https(self):
        pack = _pack()
        matches = pack.evaluate(_req(
            path="/api/users",
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
            scheme="https",
        ))
        assert "API-AUTH-002" not in _rule_ids(matches)

    def test_not_fired_for_bearer_over_http(self):
        pack = _pack()
        matches = pack.evaluate(_req(
            path="/api/users",
            headers=_auth_header("Bearer token123"),
            scheme="http",
        ))
        assert "API-AUTH-002" not in _rule_ids(matches)

    def test_auth002_is_critical(self):
        pack = _pack()
        matches = pack.evaluate(_req(
            path="/api/users",
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
            scheme="http",
        ))
        m = next(m for m in matches if m.rule_id == "API-AUTH-002")
        assert m.severity == Severity.CRITICAL


# ===========================================================================
# API-BOLA-001 / API-BOLA-002: IDOR
# ===========================================================================

class TestAPIBOLA:
    def test_bola001_fires_for_numeric_id_path(self):
        pack = _pack()
        matches = pack.evaluate(_req(path="/api/users/42", headers=_auth_header()))
        assert "API-BOLA-001" in _rule_ids(matches)

    def test_bola001_is_medium_log(self):
        pack = _pack()
        matches = pack.evaluate(_req(path="/api/users/42", headers=_auth_header()))
        m = next(m for m in matches if m.rule_id == "API-BOLA-001")
        assert m.severity == Severity.MEDIUM
        assert m.action == Action.LOG

    def test_bola001_not_fired_for_named_resource(self):
        pack = _pack()
        matches = pack.evaluate(_req(path="/api/users/alice", headers=_auth_header()))
        assert "API-BOLA-001" not in _rule_ids(matches)

    def test_bola002_fires_on_burst(self):
        pack = ApiSecurityRulepack(idor_burst_threshold=10)
        matches = pack.evaluate(_req(
            path="/api/items/99",
            headers=_auth_header(),
            session_count=15,
        ))
        assert "API-BOLA-002" in _rule_ids(matches)

    def test_bola002_not_fired_below_threshold(self):
        pack = ApiSecurityRulepack(idor_burst_threshold=10)
        matches = pack.evaluate(_req(
            path="/api/items/99",
            headers=_auth_header(),
            session_count=5,
        ))
        assert "API-BOLA-002" not in _rule_ids(matches)

    def test_bola002_is_high_block(self):
        pack = ApiSecurityRulepack(idor_burst_threshold=5)
        matches = pack.evaluate(_req(
            path="/api/items/7",
            headers=_auth_header(),
            session_count=10,
        ))
        m = next(m for m in matches if m.rule_id == "API-BOLA-002")
        assert m.severity == Severity.HIGH
        assert m.action == Action.BLOCK


# ===========================================================================
# API-INJECT-001: GraphQL introspection
# ===========================================================================

class TestAPIGraphQLIntrospection:
    def test_fires_for_introspection_query(self):
        pack = _pack()
        body = '{"query": "{ __schema { types { name } } }"}'
        matches = pack.evaluate(_req(
            path="/graphql",
            method="POST",
            body=body,
            headers=_auth_header(),
        ))
        assert "API-INJECT-001" in _rule_ids(matches)

    def test_not_fired_for_normal_query(self):
        pack = _pack()
        body = '{"query": "{ users { id name } }"}'
        matches = pack.evaluate(_req(
            path="/graphql",
            method="POST",
            body=body,
            headers=_auth_header(),
        ))
        assert "API-INJECT-001" not in _rule_ids(matches)

    def test_fires_on_non_graphql_path_with_introspection_in_body(self):
        pack = _pack()
        body = '{"query":"__schema {types}"}'
        matches = pack.evaluate(_req(
            path="/api/gql",
            method="POST",
            body=body,
            headers=_auth_header(),
        ))
        assert "API-INJECT-001" in _rule_ids(matches)

    def test_inject001_is_medium(self):
        pack = _pack()
        body = '{"query": "{ __schema { types { name } } }"}'
        matches = pack.evaluate(_req(path="/graphql", method="POST", body=body,
                                    headers=_auth_header()))
        m = next(m for m in matches if m.rule_id == "API-INJECT-001")
        assert m.severity == Severity.MEDIUM


# ===========================================================================
# API-INJECT-002: GraphQL batch
# ===========================================================================

class TestAPIGraphQLBatch:
    def test_fires_when_operations_exceed_limit(self):
        pack = ApiSecurityRulepack(graphql_batch_limit=3)
        body = (
            '{"query":"query A{users{id}}"}'
            '{"query":"query B{items{id}}"}'
            '{"query":"query C{orders{id}}"}'
            '{"query":"mutation D{deleteUser(id:1){id}}"}'
            '{"query":"query E{products{id}}"}'
        )
        matches = pack.evaluate(_req(path="/graphql", method="POST", body=body,
                                    headers=_auth_header()))
        assert "API-INJECT-002" in _rule_ids(matches)

    def test_not_fired_at_or_below_limit(self):
        pack = ApiSecurityRulepack(graphql_batch_limit=5)
        body = '{"query":"query A{users{id}}"} {"query":"query B{items{id}}"}'
        matches = pack.evaluate(_req(path="/graphql", method="POST", body=body,
                                    headers=_auth_header()))
        assert "API-INJECT-002" not in _rule_ids(matches)


# ===========================================================================
# API-INJECT-003: SSTI
# ===========================================================================

class TestAPIInjectSSTI:
    def test_fires_for_jinja2_token(self):
        pack = _pack()
        matches = pack.evaluate(_req(
            path="/api/template",
            headers=_auth_header(),
            body='{"template": "{{7*7}}"}',
        ))
        assert "API-INJECT-003" in _rule_ids(matches)

    def test_fires_for_el_expression(self):
        pack = _pack()
        matches = pack.evaluate(_req(
            path="/api/render",
            headers=_auth_header(),
            body='name=${7*7}',
        ))
        assert "API-INJECT-003" in _rule_ids(matches)

    def test_fires_for_erb_token(self):
        pack = _pack()
        matches = pack.evaluate(_req(
            path="/api/render",
            headers=_auth_header(),
            body="output: <%= system('id') %>",
        ))
        assert "API-INJECT-003" in _rule_ids(matches)

    def test_not_fired_for_normal_body(self):
        pack = _pack()
        matches = pack.evaluate(_req(
            path="/api/users",
            headers=_auth_header(),
            body='{"name": "Alice", "email": "alice@example.com"}',
        ))
        assert "API-INJECT-003" not in _rule_ids(matches)

    def test_ssti_is_critical_block(self):
        pack = _pack()
        matches = pack.evaluate(_req(
            path="/api/render",
            headers=_auth_header(),
            body='{{7*7}}',
        ))
        m = next(m for m in matches if m.rule_id == "API-INJECT-003")
        assert m.severity == Severity.CRITICAL
        assert m.action == Action.BLOCK

    def test_fires_from_query_params(self):
        pack = _pack()
        matches = pack.evaluate(_req(
            path="/api/search",
            headers=_auth_header(),
            params={"q": "{{7*7}}"},
        ))
        assert "API-INJECT-003" in _rule_ids(matches)


# ===========================================================================
# API-VERB-001: Verb tampering
# ===========================================================================

class TestAPIVerbTampering:
    def test_trace_on_protected_path_fires(self):
        pack = _pack()
        matches = pack.evaluate(_req(method="TRACE", path="/api/admin"))
        assert "API-VERB-001" in _rule_ids(matches)

    def test_head_on_protected_path_fires(self):
        pack = _pack()
        matches = pack.evaluate(_req(method="HEAD", path="/v1/secure"))
        assert "API-VERB-001" in _rule_ids(matches)

    def test_options_returns_log_not_block(self):
        pack = _pack()
        matches = pack.evaluate(_req(method="OPTIONS", path="/api/data"))
        verb_matches = [m for m in matches if m.rule_id == "API-VERB-001"]
        assert len(verb_matches) == 1
        assert verb_matches[0].action == Action.LOG

    def test_get_not_flagged(self):
        pack = _pack()
        matches = pack.evaluate(_req(method="GET", path="/api/users", headers=_auth_header()))
        assert "API-VERB-001" not in _rule_ids(matches)

    def test_verb_not_flagged_on_non_protected_path(self):
        pack = _pack()
        matches = pack.evaluate(_req(method="TRACE", path="/public/page"))
        assert "API-VERB-001" not in _rule_ids(matches)


# ===========================================================================
# API-EXPOSE-001: Sensitive field exposure
# ===========================================================================

class TestAPIExpose001:
    def test_fires_for_password_field_in_response(self):
        pack = ApiSecurityRulepack(check_response_body=True)
        req = _req(headers=_auth_header())
        req["response_body"] = '{"id": 1, "password": "secret123"}'
        matches = pack.evaluate(req)
        assert "API-EXPOSE-001" in _rule_ids(matches)

    def test_fires_for_api_key_in_response(self):
        pack = ApiSecurityRulepack(check_response_body=True)
        req = _req(headers=_auth_header())
        req["response_body"] = '{"user": "alice", "api_key": "abc123"}'
        matches = pack.evaluate(req)
        assert "API-EXPOSE-001" in _rule_ids(matches)

    def test_not_fired_when_check_response_disabled(self):
        pack = ApiSecurityRulepack(check_response_body=False)
        req = _req(headers=_auth_header())
        req["response_body"] = '{"password": "secret"}'
        matches = pack.evaluate(req)
        assert "API-EXPOSE-001" not in _rule_ids(matches)

    def test_not_fired_for_clean_response(self):
        pack = ApiSecurityRulepack(check_response_body=True)
        req = _req(headers=_auth_header())
        req["response_body"] = '{"id": 1, "name": "Alice", "email": "a@b.com"}'
        matches = pack.evaluate(req)
        assert "API-EXPOSE-001" not in _rule_ids(matches)

    def test_expose001_is_high_log(self):
        pack = ApiSecurityRulepack(check_response_body=True)
        req = _req(headers=_auth_header())
        req["response_body"] = '{"secret": "abc"}'
        matches = pack.evaluate(req)
        m = next(m for m in matches if m.rule_id == "API-EXPOSE-001")
        assert m.severity == Severity.HIGH
        assert m.action == Action.LOG


# ===========================================================================
# API-RATE-001: Auth endpoint burst
# ===========================================================================

class TestAPIRate001:
    def test_fires_on_burst_to_login(self):
        pack = ApiSecurityRulepack(rate_limit_burst=20)
        matches = pack.evaluate(_req(path="/v1/login", session_count=25))
        assert "API-RATE-001" in _rule_ids(matches)

    def test_fires_on_burst_to_token_endpoint(self):
        pack = ApiSecurityRulepack(rate_limit_burst=10)
        matches = pack.evaluate(_req(path="/auth/token", session_count=15))
        assert "API-RATE-001" in _rule_ids(matches)

    def test_not_fired_below_threshold(self):
        pack = ApiSecurityRulepack(rate_limit_burst=20)
        matches = pack.evaluate(_req(path="/v1/login", session_count=5))
        assert "API-RATE-001" not in _rule_ids(matches)

    def test_not_fired_for_non_auth_endpoint(self):
        pack = ApiSecurityRulepack(rate_limit_burst=5)
        matches = pack.evaluate(_req(path="/api/products", session_count=100,
                                     headers=_auth_header()))
        assert "API-RATE-001" not in _rule_ids(matches)

    def test_rate001_is_high_block(self):
        pack = ApiSecurityRulepack(rate_limit_burst=5)
        matches = pack.evaluate(_req(path="/login", session_count=10))
        m = next(m for m in matches if m.rule_id == "API-RATE-001")
        assert m.severity == Severity.HIGH
        assert m.action == Action.BLOCK


# ===========================================================================
# Multiple rules firing simultaneously
# ===========================================================================

class TestMultipleRules:
    def test_no_auth_plus_numeric_id(self):
        pack = _pack()
        matches = pack.evaluate(_req(path="/api/users/42"))
        ids = _rule_ids(matches)
        assert "API-AUTH-001" in ids
        assert "API-BOLA-001" in ids

    def test_clean_request_produces_no_matches(self):
        pack = _pack()
        matches = pack.evaluate(_req(
            method="GET",
            path="/api/users",
            headers=_auth_header(),
            scheme="https",
        ))
        assert len(matches) == 0

    def test_body_dict_accepted(self):
        pack = _pack()
        matches = pack.evaluate(_req(
            path="/api/render",
            headers=_auth_header(),
            body={"template": "{{7*7}}"},
        ))
        assert "API-INJECT-003" in _rule_ids(matches)
