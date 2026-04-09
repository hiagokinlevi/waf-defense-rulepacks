"""
Tests for shared/rulepacks/nginx_modsec_stubs.py

Validates:
  - _zone_name produces safe identifier from rule name
  - _zone_name handles spaces, special chars, leading/trailing underscores
  - _nginx_rate produces r/s for high-throughput rules
  - _nginx_rate produces r/m for low-throughput rules
  - _nginx_rate handles window_seconds <= 0 safely
  - generate_nginx_rate_limit contains zone declaration
  - generate_nginx_rate_limit contains limit_req directive
  - generate_nginx_rate_limit contains rate value
  - generate_nginx_rate_limit contains path_pattern
  - generate_nginx_rate_limit BLOCK action sets limit_req_status 429
  - generate_nginx_rate_limit LOG action disables status line
  - generate_nginx_rate_limit burst is at least 1
  - export_pack_nginx contains all rule names
  - export_pack_nginx includes pack name header
  - generate_modsec_rule contains SecAction with counter init
  - generate_modsec_rule contains SecRule with threshold check
  - generate_modsec_rule uses correct rule IDs (base, base+1)
  - generate_modsec_rule BLOCK action uses deny,status:429
  - generate_modsec_rule LOG action uses pass,log
  - generate_modsec_rule includes expirevar with window_seconds
  - generate_modsec_rule includes requests threshold in SecRule
  - generate_modsec_rule includes rule name in msg
  - export_pack_modsec contains all rules
  - export_pack_modsec assigns sequential IDs
  - export_pack_modsec custom rule_id_start respected
  - waf_export_cmd --dry-run prints filenames without writing
  - waf_export_cmd --vendor cloudflare writes JSON with rules key
  - waf_export_cmd --vendor nginx writes .conf file
  - waf_export_cmd --vendor modsec writes .conf file
  - waf_export_cmd --vendor all writes files for all vendors
  - waf_export_cmd --pack login-bruteforce limits to one pack
  - _export_pack raises ValueError for unknown vendor
  - _output_filename builds correct name with extension
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.rulepacks.nginx_modsec_stubs import (
    _zone_name,
    _nginx_rate,
    export_pack_modsec,
    export_pack_nginx,
    generate_modsec_rule,
    generate_nginx_rate_limit,
)
from shared.rulepacks.rate_limit_rulepack import (
    RateLimitAction,
    RateLimitRule,
    RateLimitScope,
    build_login_bruteforce_pack,
    build_api_protection_pack,
)
from cli.waf_export_cmd import (
    waf_export_cmd,
    _export_pack,
    _output_filename,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rule(
    name: str = "Login Brute-Force Protection",
    path: str = "/login",
    requests: int = 10,
    window: int = 60,
    scope: RateLimitScope = RateLimitScope.PER_IP,
    action: RateLimitAction = RateLimitAction.BLOCK,
) -> RateLimitRule:
    return RateLimitRule(
        name=name,
        path_pattern=path,
        requests=requests,
        window_seconds=window,
        scope=scope,
        action=action,
    )


# ---------------------------------------------------------------------------
# _zone_name
# ---------------------------------------------------------------------------

class TestZoneName:

    def test_spaces_replaced_with_underscore(self):
        r = _rule(name="My Rule Name")
        assert " " not in _zone_name(r)

    def test_lowercase_output(self):
        r = _rule(name="LOGIN RULE")
        assert _zone_name(r) == "login_rule"

    def test_special_chars_removed(self):
        r = _rule(name="rule/v2!@#")
        z = _zone_name(r)
        assert re.match(r"^[a-z0-9_]+$", z), f"Non-safe chars in: {z}"

    def test_non_empty_result(self):
        # Use a minimal valid name that strips to only underscores after sanitization
        r = _rule(name="a")   # shortest valid name
        z = _zone_name(r)
        assert len(z) > 0


import re  # noqa: E402 — needed by TestZoneName above


# ---------------------------------------------------------------------------
# _nginx_rate
# ---------------------------------------------------------------------------

class TestNginxRate:

    def test_high_throughput_uses_rps(self):
        r = _rule(requests=120, window=60)   # 2 r/s
        assert "r/s" in _nginx_rate(r)

    def test_low_throughput_uses_rpm(self):
        r = _rule(requests=5, window=60)    # 0.083 r/s → expressed as r/m
        rate = _nginx_rate(r)
        assert "r/m" in rate

    def test_rate_at_least_one(self):
        r = _rule(requests=1, window=3600)  # very low — still >= 1
        rate = _nginx_rate(r)
        val = int(rate.rstrip("r/sm"))
        assert val >= 1

    def test_zero_window_safe(self):
        # Call _nginx_rate directly with a mock object to test the guard branch
        class _MockRule:
            requests = 10
            window_seconds = 0
        rate = _nginx_rate(_MockRule())
        assert rate == "1r/s"


# ---------------------------------------------------------------------------
# generate_nginx_rate_limit
# ---------------------------------------------------------------------------

class TestGenerateNginxRateLimit:

    def test_contains_limit_req_zone(self):
        r = _rule()
        conf = generate_nginx_rate_limit(r)
        assert "limit_req_zone" in conf

    def test_contains_limit_req(self):
        r = _rule()
        conf = generate_nginx_rate_limit(r)
        assert "limit_req zone=" in conf

    def test_contains_path_pattern(self):
        r = _rule(path="/api/v2/login")
        conf = generate_nginx_rate_limit(r)
        assert "/api/v2/login" in conf

    def test_block_action_sets_status_429(self):
        r = _rule(action=RateLimitAction.BLOCK)
        conf = generate_nginx_rate_limit(r)
        assert "limit_req_status 429" in conf

    def test_log_action_disables_status(self):
        r = _rule(action=RateLimitAction.LOG)
        conf = generate_nginx_rate_limit(r)
        # status line is commented out for log-only
        assert "# limit_req_status 429" in conf

    def test_burst_is_at_least_one(self):
        r = _rule(requests=1)
        conf = generate_nginx_rate_limit(r)
        # burst=max(1, 1//2) = 1
        assert "burst=1" in conf

    def test_zone_name_in_directive(self):
        r = _rule(name="My Login Rule")
        conf = generate_nginx_rate_limit(r)
        assert "my_login_rule" in conf

    def test_rate_in_directive(self):
        r = _rule(requests=10, window=60)
        conf = generate_nginx_rate_limit(r)
        # 10/60 = 0.16 r/s → expressed as r/m
        assert "r/m" in conf or "r/s" in conf

    def test_custom_zone_size_mb(self):
        r = _rule()
        conf = generate_nginx_rate_limit(r, zone_size_mb=20)
        assert "20m" in conf


# ---------------------------------------------------------------------------
# export_pack_nginx
# ---------------------------------------------------------------------------

class TestExportPackNginx:

    def test_contains_pack_name_header(self):
        pack = build_login_bruteforce_pack()
        conf = export_pack_nginx(pack)
        assert pack.name in conf

    def test_contains_all_rule_names(self):
        pack = build_login_bruteforce_pack()
        conf = export_pack_nginx(pack)
        for rule in pack.rules:
            assert rule.name in conf

    def test_multiple_limit_req_zone_blocks(self):
        pack = build_api_protection_pack()
        conf = export_pack_nginx(pack)
        assert conf.count("limit_req_zone") == len(pack.rules)


# ---------------------------------------------------------------------------
# generate_modsec_rule
# ---------------------------------------------------------------------------

class TestGenerateModsecRule:

    def test_contains_secaction(self):
        r = _rule()
        conf = generate_modsec_rule(r)
        assert "SecAction" in conf

    def test_contains_secrule(self):
        r = _rule()
        conf = generate_modsec_rule(r)
        assert "SecRule" in conf

    def test_rule_id_base_in_secaction(self):
        r = _rule()
        conf = generate_modsec_rule(r, rule_id_base=9001000)
        assert "id:9001000" in conf

    def test_rule_id_plus_one_in_secrule(self):
        r = _rule()
        conf = generate_modsec_rule(r, rule_id_base=9001000)
        assert "id:9001001" in conf

    def test_block_action_deny_429(self):
        r = _rule(action=RateLimitAction.BLOCK)
        conf = generate_modsec_rule(r)
        assert "deny,status:429" in conf

    def test_log_action_pass_log(self):
        r = _rule(action=RateLimitAction.LOG)
        conf = generate_modsec_rule(r)
        assert "pass,log" in conf

    def test_expirevar_uses_window_seconds(self):
        r = _rule(window=300)
        conf = generate_modsec_rule(r)
        assert "expirevar" in conf
        assert "300" in conf

    def test_threshold_uses_requests_count(self):
        r = _rule(requests=25)
        conf = generate_modsec_rule(r)
        assert "@gt 25" in conf

    def test_rule_name_in_msg(self):
        r = _rule(name="API Rate Limit")
        conf = generate_modsec_rule(r)
        assert "API Rate Limit" in conf

    def test_initcol_in_secaction(self):
        r = _rule()
        conf = generate_modsec_rule(r)
        assert "initcol" in conf


# ---------------------------------------------------------------------------
# export_pack_modsec
# ---------------------------------------------------------------------------

class TestExportPackModsec:

    def test_contains_pack_name_header(self):
        pack = build_login_bruteforce_pack()
        conf = export_pack_modsec(pack)
        assert pack.name in conf

    def test_each_rule_has_two_ids(self):
        pack = build_login_bruteforce_pack()
        conf = export_pack_modsec(pack, rule_id_start=9000000)
        # Each rule has SecAction (id:N) + SecRule (id:N+1)
        for i in range(len(pack.rules)):
            base = 9000000 + i * 2
            assert f"id:{base}" in conf
            assert f"id:{base + 1}" in conf

    def test_custom_rule_id_start(self):
        pack = build_api_protection_pack()
        conf = export_pack_modsec(pack, rule_id_start=8000000)
        assert "id:8000000" in conf

    def test_rule_count_comment(self):
        pack = build_login_bruteforce_pack()
        conf = export_pack_modsec(pack)
        assert str(len(pack.rules)) in conf


# ---------------------------------------------------------------------------
# _export_pack
# ---------------------------------------------------------------------------

class TestExportPack:

    def test_cloudflare_produces_json(self):
        pack = build_login_bruteforce_pack()
        out = _export_pack(pack, "cloudflare")
        data = json.loads(out)
        assert "rules" in data
        assert data["vendor"] == "cloudflare"

    def test_aws_produces_json(self):
        pack = build_login_bruteforce_pack()
        out = _export_pack(pack, "aws")
        data = json.loads(out)
        assert "rules" in data

    def test_azure_produces_json(self):
        pack = build_login_bruteforce_pack()
        out = _export_pack(pack, "azure")
        data = json.loads(out)
        assert "rules" in data

    def test_nginx_produces_conf_string(self):
        pack = build_login_bruteforce_pack()
        out = _export_pack(pack, "nginx")
        assert "limit_req_zone" in out

    def test_modsec_produces_conf_string(self):
        pack = build_login_bruteforce_pack()
        out = _export_pack(pack, "modsec")
        assert "SecAction" in out

    def test_unknown_vendor_raises_value_error(self):
        pack = build_login_bruteforce_pack()
        with pytest.raises(ValueError, match="Unsupported vendor"):
            _export_pack(pack, "imperva")


# ---------------------------------------------------------------------------
# _output_filename
# ---------------------------------------------------------------------------

class TestOutputFilename:

    def test_cloudflare_json_extension(self):
        assert _output_filename("cloudflare", "login-bruteforce").endswith(".json")

    def test_nginx_conf_extension(self):
        assert _output_filename("nginx", "api-protection").endswith(".conf")

    def test_modsec_conf_extension(self):
        assert _output_filename("modsec", "api-protection").endswith(".conf")

    def test_filename_contains_vendor(self):
        assert "cloudflare" in _output_filename("cloudflare", "login-bruteforce")

    def test_filename_contains_pack_name(self):
        fname = _output_filename("aws", "login-bruteforce")
        assert "login" in fname or "bruteforce" in fname


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------

class TestWafExportCmd:

    def test_dry_run_no_files_written(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(
            waf_export_cmd,
            ["--vendor", "cloudflare", "--output-dir", str(tmp_path), "--dry-run"],
        )
        assert result.exit_code == 0
        assert "[DRY RUN]" in result.output
        assert len(list(tmp_path.iterdir())) == 0

    def test_dry_run_shows_filenames(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(
            waf_export_cmd,
            ["--vendor", "cloudflare", "--output-dir", str(tmp_path), "--dry-run"],
        )
        assert "Would write" in result.output

    def test_vendor_cloudflare_writes_json_file(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(
            waf_export_cmd,
            ["--vendor", "cloudflare", "--pack", "login-bruteforce", "--output-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        files = list(tmp_path.glob("*.json"))
        assert len(files) >= 1

    def test_vendor_nginx_writes_conf_file(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(
            waf_export_cmd,
            ["--vendor", "nginx", "--pack", "api-protection", "--output-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        files = list(tmp_path.glob("*.conf"))
        assert len(files) >= 1

    def test_vendor_modsec_writes_conf_file(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(
            waf_export_cmd,
            ["--vendor", "modsec", "--output-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        files = list(tmp_path.glob("*.conf"))
        assert len(files) >= 1

    def test_vendor_all_writes_files_for_every_vendor(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(
            waf_export_cmd,
            ["--vendor", "all", "--pack", "login-bruteforce", "--output-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        all_files = list(tmp_path.iterdir())
        # Should have one file per vendor (5 vendors × 1 pack = 5 files)
        assert len(all_files) == 5

    def test_pack_login_bruteforce_limits_output(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(
            waf_export_cmd,
            ["--vendor", "cloudflare", "--pack", "login-bruteforce", "--output-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        files = list(tmp_path.glob("cloudflare_login*.json"))
        assert len(files) == 1

    def test_stdout_flag_prints_content(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(
            waf_export_cmd,
            [
                "--vendor", "cloudflare",
                "--pack", "login-bruteforce",
                "--output-dir", str(tmp_path),
                "--stdout",
            ],
        )
        assert result.exit_code == 0
        assert "rules" in result.output  # JSON content printed to stdout

    def test_export_complete_message(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(
            waf_export_cmd,
            ["--vendor", "aws", "--output-dir", str(tmp_path)],
        )
        assert "Export complete" in result.output
