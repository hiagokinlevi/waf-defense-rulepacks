#!/usr/bin/env python3
"""
Unit tests for shared/validators/validate_pack.py

Run with:
    python -m pytest tests/test_validator.py -v

Or:
    python tests/test_validator.py
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

# Add the shared/validators directory to path so we can import validate_pack
REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "shared" / "validators"))

from validate_pack import validate_pack, should_skip, REQUIRED_FIELDS


class TestValidatePack(unittest.TestCase):
    """Tests for the validate_pack() function."""

    def _write_pack(self, data: dict) -> Path:
        """
        Helper: write a pack dict to a temporary JSON file and return the path.
        The temp file is in the test's temporary directory.
        """
        tmp = tempfile.NamedTemporaryFile(
            suffix=".json",
            mode="w",
            delete=False,
            dir=self.temp_dir,
        )
        json.dump(data, tmp)
        tmp.close()
        return Path(tmp.name)

    def setUp(self):
        """Create a temporary directory for test pack files."""
        import tempfile as _tempfile
        self.temp_dir_obj = _tempfile.TemporaryDirectory()
        self.temp_dir = self.temp_dir_obj.name

    def tearDown(self):
        """Clean up temporary directory."""
        self.temp_dir_obj.cleanup()

    def _valid_pack(self) -> dict:
        """Return a minimal valid pack dict."""
        return {
            "name": "Test Pack for Unit Tests",
            "vendor": "cloudflare",
            "category": "sqli_protection",
            "app_context": "generic",
            "objective": "Detect and block common SQL injection patterns in requests",
            "risk_mitigated": "SQL injection leading to data exfiltration",
            "severity": "critical",
            "mode": "block",
            "version": "1.0.0",
            "maturity": "reviewed",
        }

    # -------------------------------------------------------------------------
    # Tests: Valid packs
    # -------------------------------------------------------------------------

    def test_valid_pack_returns_no_errors(self):
        """A fully valid pack should return an empty error list."""
        pack_path = self._write_pack(self._valid_pack())
        errors = validate_pack(pack_path)
        self.assertEqual(errors, [], f"Expected no errors, got: {errors}")

    def test_valid_pack_all_vendors(self):
        """All supported vendor values should be accepted."""
        valid_vendors = [
            "cloudflare", "aws-waf", "azure-waf", "f5", "fortiweb",
            "imperva", "checkpoint", "modsecurity", "nginx", "generic",
        ]
        for vendor in valid_vendors:
            with self.subTest(vendor=vendor):
                pack = self._valid_pack()
                pack["vendor"] = vendor
                pack_path = self._write_pack(pack)
                errors = validate_pack(pack_path)
                self.assertEqual(errors, [], f"Vendor '{vendor}' should be valid, got: {errors}")

    def test_valid_pack_all_maturities(self):
        """All valid maturity values should be accepted."""
        valid_maturities = ["draft", "reviewed", "tested", "operational", "mature"]
        for maturity in valid_maturities:
            with self.subTest(maturity=maturity):
                pack = self._valid_pack()
                pack["maturity"] = maturity
                pack_path = self._write_pack(pack)
                errors = validate_pack(pack_path)
                self.assertEqual(errors, [], f"Maturity '{maturity}' should be valid, got: {errors}")

    def test_valid_pack_all_severities(self):
        """All valid severity values should be accepted."""
        valid_severities = ["critical", "high", "medium", "low", "informational"]
        for severity in valid_severities:
            with self.subTest(severity=severity):
                pack = self._valid_pack()
                pack["severity"] = severity
                pack_path = self._write_pack(pack)
                errors = validate_pack(pack_path)
                self.assertEqual(errors, [], f"Severity '{severity}' should be valid, got: {errors}")

    def test_valid_pack_with_optional_fields(self):
        """Pack with all optional fields should also be valid."""
        pack = self._valid_pack()
        pack.update({
            "potential_side_effects": "May produce false positives on search endpoints",
            "tuning_notes": "Add path exclusions for /api/search",
            "deployment_notes": "Deploy in log mode for 72h first",
            "monitoring_notes": "Watch for block rate spikes",
            "references": ["https://owasp.org/www-project-top-ten/"],
            "tags": ["sqli", "injection", "critical"],
            "recommended_for": ["web_apps", "apis"],
        })
        pack_path = self._write_pack(pack)
        errors = validate_pack(pack_path)
        self.assertEqual(errors, [], f"Pack with optional fields should be valid, got: {errors}")

    # -------------------------------------------------------------------------
    # Tests: Missing required fields
    # -------------------------------------------------------------------------

    def test_missing_name_returns_error(self):
        """Pack missing 'name' should fail validation."""
        pack = self._valid_pack()
        del pack["name"]
        pack_path = self._write_pack(pack)
        errors = validate_pack(pack_path)
        self.assertTrue(
            any("name" in e for e in errors),
            f"Expected error about missing 'name', got: {errors}"
        )

    def test_missing_vendor_returns_error(self):
        """Pack missing 'vendor' should fail validation."""
        pack = self._valid_pack()
        del pack["vendor"]
        pack_path = self._write_pack(pack)
        errors = validate_pack(pack_path)
        self.assertTrue(
            any("vendor" in e for e in errors),
            f"Expected error about missing 'vendor', got: {errors}"
        )

    def test_all_required_fields_individually(self):
        """Each required field, when removed, should produce a validation error."""
        for field in REQUIRED_FIELDS:
            with self.subTest(missing_field=field):
                pack = self._valid_pack()
                del pack[field]
                pack_path = self._write_pack(pack)
                errors = validate_pack(pack_path)
                self.assertTrue(
                    len(errors) > 0,
                    f"Removing '{field}' should produce errors, but got none"
                )

    # -------------------------------------------------------------------------
    # Tests: Invalid enum values
    # -------------------------------------------------------------------------

    def test_invalid_vendor_returns_error(self):
        """An unrecognized vendor value should fail validation."""
        pack = self._valid_pack()
        pack["vendor"] = "not-a-real-vendor"
        pack_path = self._write_pack(pack)
        errors = validate_pack(pack_path)
        self.assertTrue(
            any("vendor" in e.lower() for e in errors),
            f"Expected error about invalid 'vendor', got: {errors}"
        )

    def test_invalid_maturity_returns_error(self):
        """An unrecognized maturity value should fail validation."""
        pack = self._valid_pack()
        pack["maturity"] = "unknown-maturity"
        pack_path = self._write_pack(pack)
        errors = validate_pack(pack_path)
        self.assertTrue(
            any("maturity" in e.lower() for e in errors),
            f"Expected error about invalid 'maturity', got: {errors}"
        )

    def test_invalid_severity_returns_error(self):
        """An unrecognized severity value should fail validation."""
        pack = self._valid_pack()
        pack["severity"] = "super-critical"
        pack_path = self._write_pack(pack)
        errors = validate_pack(pack_path)
        self.assertTrue(
            any("severity" in e.lower() for e in errors),
            f"Expected error about invalid 'severity', got: {errors}"
        )

    def test_invalid_mode_returns_error(self):
        """An unrecognized mode value should fail validation."""
        pack = self._valid_pack()
        pack["mode"] = "destroy"
        pack_path = self._write_pack(pack)
        errors = validate_pack(pack_path)
        self.assertTrue(
            any("mode" in e.lower() for e in errors),
            f"Expected error about invalid 'mode', got: {errors}"
        )

    # -------------------------------------------------------------------------
    # Tests: Version format
    # -------------------------------------------------------------------------

    def test_invalid_version_format(self):
        """Version strings that are not semver (x.y.z) should fail."""
        invalid_versions = ["1.0", "v1.0.0", "1.0.0.0", "latest", "1"]
        for version in invalid_versions:
            with self.subTest(version=version):
                pack = self._valid_pack()
                pack["version"] = version
                pack_path = self._write_pack(pack)
                errors = validate_pack(pack_path)
                self.assertTrue(
                    any("version" in e.lower() for e in errors),
                    f"Version '{version}' should be invalid, got errors: {errors}"
                )

    def test_valid_version_formats(self):
        """Valid semver strings should be accepted."""
        valid_versions = ["1.0.0", "0.1.0", "2.3.4", "10.0.1"]
        for version in valid_versions:
            with self.subTest(version=version):
                pack = self._valid_pack()
                pack["version"] = version
                pack_path = self._write_pack(pack)
                errors = validate_pack(pack_path)
                self.assertFalse(
                    any("version" in e.lower() for e in errors),
                    f"Version '{version}' should be valid, but got error: {errors}"
                )

    # -------------------------------------------------------------------------
    # Tests: JSON syntax errors
    # -------------------------------------------------------------------------

    def test_invalid_json_returns_error(self):
        """A file with invalid JSON should return a syntax error."""
        invalid_json_path = Path(self.temp_dir) / "invalid.json"
        invalid_json_path.write_text("{not valid json: }")
        errors = validate_pack(invalid_json_path)
        self.assertTrue(
            any("json" in e.lower() or "syntax" in e.lower() for e in errors),
            f"Invalid JSON should produce a JSON error, got: {errors}"
        )

    def test_nonexistent_file_returns_error(self):
        """A path to a non-existent file should return an error."""
        nonexistent_path = Path(self.temp_dir) / "does_not_exist.json"
        errors = validate_pack(nonexistent_path)
        self.assertTrue(len(errors) > 0, "Non-existent file should produce errors")

    def test_container_template_with_k1n_metadata_is_skipped(self):
        """Provider policy templates with _k1n_metadata should not fail pack validation."""
        template = {
            "_k1n_metadata": {
                "name": "Template only",
                "vendor": "aws-waf",
                "version": "1.0.0",
            },
            "Rules": [],
        }
        pack_path = self._write_pack(template)
        errors = validate_pack(pack_path)
        self.assertEqual(errors, [], f"Template files should be skipped, got: {errors}")

    # -------------------------------------------------------------------------
    # Tests: should_skip()
    # -------------------------------------------------------------------------

    def test_should_skip_schemas_directory(self):
        """Files in 'schemas' directories should be skipped."""
        path = Path("/repo/shared/schemas/pack_metadata.json")
        self.assertTrue(should_skip(path))

    def test_should_skip_terraform_directory(self):
        """Files in 'terraform' directories should be skipped."""
        path = Path("/repo/cloudflare/terraform/main.tf.json")
        self.assertTrue(should_skip(path))

    def test_should_skip_virtualenv_metadata(self):
        """Installed package JSON in local virtualenvs should not be treated as packs."""
        path = Path(
            "/repo/.venv_install/lib/python3.13/site-packages/"
            "k1n_waf_defense_rulepacks-0.1.0.dist-info/direct_url.json"
        )
        self.assertTrue(should_skip(path))

    def test_should_not_skip_waf_rules(self):
        """Regular WAF rule files should NOT be skipped."""
        path = Path("/repo/cloudflare/waf-rules/block_sqli.json")
        self.assertFalse(should_skip(path))

    def test_should_not_skip_rate_limits(self):
        """Rate limit pack files should NOT be skipped."""
        path = Path("/repo/cloudflare/rate-limits/login_rate_limit.json")
        self.assertFalse(should_skip(path))


class TestValidateRealPacks(unittest.TestCase):
    """Integration tests that validate the actual pack files in the repository."""

    def test_block_sqli_pack_is_valid(self):
        """The block_sqli.json pack should pass validation."""
        pack_path = REPO_ROOT / "cloudflare" / "waf-rules" / "block_sqli.json"
        if not pack_path.exists():
            self.skipTest(f"Pack file not found: {pack_path}")
        errors = validate_pack(pack_path)
        self.assertEqual(errors, [], f"block_sqli.json should be valid, got: {errors}")

    def test_block_xss_pack_is_valid(self):
        """The block_xss.json pack should pass validation."""
        pack_path = REPO_ROOT / "cloudflare" / "waf-rules" / "block_xss.json"
        if not pack_path.exists():
            self.skipTest(f"Pack file not found: {pack_path}")
        errors = validate_pack(pack_path)
        self.assertEqual(errors, [], f"block_xss.json should be valid, got: {errors}")

    def test_protect_admin_panel_pack_is_valid(self):
        """The protect_admin_panel.json pack should pass validation."""
        pack_path = REPO_ROOT / "cloudflare" / "waf-rules" / "protect_admin_panel.json"
        if not pack_path.exists():
            self.skipTest(f"Pack file not found: {pack_path}")
        errors = validate_pack(pack_path)
        self.assertEqual(errors, [], f"protect_admin_panel.json should be valid, got: {errors}")

    def test_block_command_injection_pack_is_valid(self):
        """The block_command_injection.json pack should pass validation."""
        pack_path = REPO_ROOT / "cloudflare" / "waf-rules" / "block_command_injection.json"
        if not pack_path.exists():
            self.skipTest(f"Pack file not found: {pack_path}")
        errors = validate_pack(pack_path)
        self.assertEqual(
            errors,
            [],
            f"block_command_injection.json should be valid, got: {errors}",
        )

    def test_block_remote_file_inclusion_pack_is_valid(self):
        """The block_remote_file_inclusion.json pack should pass validation."""
        pack_path = REPO_ROOT / "cloudflare" / "waf-rules" / "block_remote_file_inclusion.json"
        if not pack_path.exists():
            self.skipTest(f"Pack file not found: {pack_path}")
        errors = validate_pack(pack_path)
        self.assertEqual(
            errors,
            [],
            f"block_remote_file_inclusion.json should be valid, got: {errors}",
        )

    def test_block_remote_file_inclusion_expression_covers_encoded_payloads(self):
        """The RFI pack should preserve file-context and encoded scheme coverage."""
        pack_path = REPO_ROOT / "cloudflare" / "waf-rules" / "block_remote_file_inclusion.json"
        if not pack_path.exists():
            self.skipTest(f"Pack file not found: {pack_path}")
        pack = json.loads(pack_path.read_text())
        expression = pack["cloudflare_expression"]
        for indicator in (
            "file=http://",
            "include=https://",
            "template=http://",
            "file=http%3a%2f%2f",
        ):
            self.assertIn(indicator, expression)

    def test_login_rate_limit_pack_is_valid(self):
        """The login_rate_limit.json pack should pass validation."""
        pack_path = REPO_ROOT / "cloudflare" / "rate-limits" / "login_rate_limit.json"
        if not pack_path.exists():
            self.skipTest(f"Pack file not found: {pack_path}")
        errors = validate_pack(pack_path)
        self.assertEqual(errors, [], f"login_rate_limit.json should be valid, got: {errors}")

    def test_bot_mitigation_pack_is_valid(self):
        """The bot_mitigation_baseline.json pack should pass validation."""
        pack_path = REPO_ROOT / "cloudflare" / "bot-rules" / "bot_mitigation_baseline.json"
        if not pack_path.exists():
            self.skipTest(f"Pack file not found: {pack_path}")
        errors = validate_pack(pack_path)
        self.assertEqual(errors, [], f"bot_mitigation_baseline.json should be valid, got: {errors}")

    def test_aws_ip_reputation_pack_is_valid(self):
        """The standalone AWS IP reputation pack should pass validation."""
        pack_path = REPO_ROOT / "aws-waf" / "rules" / "ip_reputation_managed_group.json"
        if not pack_path.exists():
            self.skipTest(f"Pack file not found: {pack_path}")
        errors = validate_pack(pack_path)
        self.assertEqual(
            errors,
            [],
            f"ip_reputation_managed_group.json should be valid, got: {errors}",
        )

    def test_aws_ip_reputation_pack_starts_in_count_mode(self):
        """The reputation pack should be safe to attach before enforcement."""
        pack_path = REPO_ROOT / "aws-waf" / "rules" / "ip_reputation_managed_group.json"
        pack = json.loads(pack_path.read_text())
        rule = pack["aws_waf_rule"]

        self.assertEqual(pack["mode"], "count")
        self.assertEqual(
            rule["Statement"]["ManagedRuleGroupStatement"]["Name"],
            "AWSManagedRulesAmazonIpReputationList",
        )
        self.assertEqual(rule["OverrideAction"], {"Count": {}})
        self.assertTrue(rule["VisibilityConfig"]["CloudWatchMetricsEnabled"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
