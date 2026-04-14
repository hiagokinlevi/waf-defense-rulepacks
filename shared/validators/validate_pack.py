#!/usr/bin/env python3
"""
WAF Pack Validator
==================
Validates that all pack JSON files conform to the repository pack metadata schema.
Reports missing required fields, invalid enum values, and JSON syntax errors.

Usage:
    python validate_pack.py --pack cloudflare/waf-rules/block_sqli.json
    python validate_pack.py --all
    python validate_pack.py --all --verbose

Requirements:
    pip install jsonschema

Exit codes:
    0 — all packs valid
    1 — one or more packs have validation errors
"""

import json
import argparse
import sys
from pathlib import Path
from urllib.parse import urlparse

# Optional: use jsonschema for full schema validation if available
try:
    from jsonschema import validate, ValidationError, Draft7Validator
    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False

# Path to the JSON Schema file — relative to this script's location
SCHEMA_PATH = Path(__file__).parent.parent / "schemas" / "pack_metadata.json"

# Required fields that must be present in every pack
REQUIRED_FIELDS = [
    "name",
    "vendor",
    "category",
    "objective",
    "risk_mitigated",
    "severity",
    "mode",
    "version",
    "maturity",
]

REQUIRED_STRING_FIELDS = tuple(REQUIRED_FIELDS)
OPTIONAL_STRING_LIST_FIELDS = ("recommended_for", "references", "tags")

# Valid enum values for key fields
VALID_VENDORS = {
    "cloudflare", "aws-waf", "azure-waf", "f5", "fortiweb",
    "imperva", "checkpoint", "modsecurity", "nginx", "generic",
}

VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}

VALID_MATURITIES = {"draft", "reviewed", "tested", "operational", "mature"}

VALID_MODES = {"block", "log", "challenge", "count", "js_challenge", "managed_challenge"}

# Keep fallback validation aligned with the schema and the pack corpus so
# malformed metadata still fails closed when jsonschema is unavailable.
VALID_CATEGORIES = {
    "sqli_protection",
    "xss_protection",
    "access_control",
    "rate_limiting",
    "bot_protection",
    "security_headers",
    "authentication_protection",
    "csrf_protection",
    "lfi_rfi_protection",
    "ssrf_protection",
    "command_injection",
    "path_traversal",
    "virtual_patch",
    "api_protection",
    "dos_protection",
    "injection",
}

VALID_APP_CONTEXTS = {
    "generic",
    "saas",
    "api",
    "e-commerce",
    "cms",
    "admin_panel",
    "microservices",
    "mobile_backend",
    "java_apps",
    "cloud_hosted",
}

# Files and directories to skip during --all validation
SKIP_PATTERNS = [
    "publish-bridge",
    "schemas",
    "examples",
    "terraform",
    ".git",
    ".pytest_cache",
    ".venv",
    "node_modules",
    "site-packages",
]


def load_schema() -> dict | None:
    """
    Load the pack metadata JSON Schema from disk.
    Returns None if the schema file does not exist or cannot be parsed.
    """
    if not SCHEMA_PATH.exists():
        return None
    try:
        with open(SCHEMA_PATH) as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"WARNING: Could not load schema file {SCHEMA_PATH}: {e}", file=sys.stderr)
        return None


def _validate_optional_string_list(
    pack: dict,
    field: str,
    *,
    require_web_url: bool = False,
) -> list[str]:
    """Validate optional metadata arrays even when full schema validation is unavailable."""
    if field not in pack:
        return []

    value = pack.get(field)
    if not isinstance(value, list):
        return [f"'{field}' must be an array of non-empty strings when provided"]

    errors = []
    for index, item in enumerate(value, start=1):
        if not isinstance(item, str) or not item.strip():
            errors.append(
                f"'{field}' item #{index} must be a non-empty string, got {type(item).__name__}"
            )
            continue

        if require_web_url:
            parsed = urlparse(item)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                errors.append(
                    f"'{field}' item #{index} must be an absolute http(s) URL, got '{item}'"
                )

    return errors


def _is_template_container(pack: dict) -> bool:
    """Return True when a JSON object is a provider template, not a standalone pack."""
    return "_k1n_metadata" in pack and not all(field in pack for field in REQUIRED_FIELDS)


def is_template_pack_file(pack_path: Path) -> bool:
    """Detect template/container JSON files that should be skipped by bulk validation."""
    try:
        with open(pack_path) as f:
            pack = json.load(f)
    except (json.JSONDecodeError, OSError):
        return False

    return isinstance(pack, dict) and _is_template_container(pack)


def validate_pack(
    pack_path: Path,
    schema: dict | None = None,
    verbose: bool = False,
) -> list[str] | None:
    """
    Validate a single pack JSON file.

    Args:
        pack_path: Path to the pack JSON file.
        schema: Optional JSON Schema dict for full validation. If None, falls back to field-level checks.
        verbose: If True, print detailed information even for valid packs.

    Returns:
        None when the file is a provider template that should be skipped, a list
        of error message strings for invalid packs, or an empty list for a valid pack.
    """
    errors = []

    # --- Step 1: Load and parse JSON ---
    try:
        with open(pack_path) as f:
            pack = json.load(f)
    except json.JSONDecodeError as e:
        return [f"Invalid JSON syntax: {e}"]
    except OSError as e:
        return [f"Cannot read file: {e}"]

    if not isinstance(pack, dict):
        return [f"Top-level JSON value must be an object, got {type(pack).__name__}"]

    # Skip container templates that carry repo metadata but are not standalone packs.
    # Examples: AWS/Azure policy templates that embed _k1n_metadata plus provider-
    # specific payload keys rather than the canonical pack fields.
    if _is_template_container(pack):
        if verbose:
            print(f"SKIP {pack_path} — template file with _k1n_metadata, not a standalone pack")
        return None

    # --- Step 2: Check required fields ---
    for field in REQUIRED_FIELDS:
        if field not in pack:
            errors.append(f"Missing required field: '{field}'")

    if errors:
        # Stop early if required fields are missing — enum validation would fail anyway
        return errors

    for field in REQUIRED_STRING_FIELDS:
        value = pack.get(field)
        if not isinstance(value, str):
            errors.append(
                f"Invalid '{field}' type '{type(value).__name__}'. Expected a non-empty string"
            )
            continue
        if not value.strip():
            errors.append(f"Required field '{field}' must not be blank or whitespace only")

    if errors:
        return errors

    # --- Step 3: Validate enum fields ---
    vendor = pack.get("vendor", "")
    if vendor not in VALID_VENDORS:
        errors.append(f"Invalid 'vendor' value '{vendor}'. Must be one of: {sorted(VALID_VENDORS)}")

    severity = pack.get("severity", "")
    if severity not in VALID_SEVERITIES:
        errors.append(f"Invalid 'severity' value '{severity}'. Must be one of: {sorted(VALID_SEVERITIES)}")

    maturity = pack.get("maturity", "")
    if maturity not in VALID_MATURITIES:
        errors.append(f"Invalid 'maturity' value '{maturity}'. Must be one of: {sorted(VALID_MATURITIES)}")

    mode = pack.get("mode", "")
    if mode not in VALID_MODES:
        errors.append(f"Invalid 'mode' value '{mode}'. Must be one of: {sorted(VALID_MODES)}")

    category = pack.get("category", "")
    if category not in VALID_CATEGORIES:
        errors.append(
            f"Invalid 'category' value '{category}'. Must be one of: {sorted(VALID_CATEGORIES)}"
        )

    if "app_context" in pack:
        app_context = pack.get("app_context")
        if not isinstance(app_context, str) or not app_context.strip():
            errors.append("'app_context' must be a non-empty string when provided")
        elif app_context not in VALID_APP_CONTEXTS:
            errors.append(
                "Invalid 'app_context' value "
                f"'{app_context}'. Must be one of: {sorted(VALID_APP_CONTEXTS)}"
            )

    for field in OPTIONAL_STRING_LIST_FIELDS:
        errors.extend(
            _validate_optional_string_list(
                pack,
                field,
                require_web_url=(field == "references"),
            )
        )

    # --- Step 4: Validate version format (semantic versioning) ---
    version = pack.get("version", "")
    parts = version.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        errors.append(f"Invalid 'version' format '{version}'. Expected semver like '1.0.0'")

    # --- Step 5: Quality checks (warnings, not errors) ---
    # These are best-practice checks — they produce warnings but do not fail validation
    warnings = []

    if len(pack.get("objective", "")) < 20:
        warnings.append("'objective' is too short. Provide a meaningful description (min 20 chars)")

    if len(pack.get("risk_mitigated", "")) < 10:
        warnings.append("'risk_mitigated' is too short. Describe the specific risk clearly")

    if "potential_side_effects" not in pack:
        warnings.append("'potential_side_effects' missing — document known false positive scenarios")

    if "deployment_notes" not in pack:
        warnings.append("'deployment_notes' missing — document the recommended deployment process")

    if verbose and warnings:
        for w in warnings:
            print(f"  WARN  {w}")

    # --- Step 6: Full JSON Schema validation (if jsonschema is available) ---
    if JSONSCHEMA_AVAILABLE and schema is not None and not errors:
        try:
            validate(instance=pack, schema=schema)
        except ValidationError as e:
            errors.append(f"JSON Schema validation error: {e.message} (path: {list(e.path)})")

    return errors


def should_skip(path: Path) -> bool:
    """
    Return True if the file path contains any of the skip patterns.
    Used to exclude non-pack files (schemas, terraform configs, etc.) from --all validation.
    """
    path_str = str(path)
    return any(pattern in path_str for pattern in SKIP_PATTERNS)


def main():
    parser = argparse.ArgumentParser(
        description="Validate WAF pack JSON files against the pack metadata schema",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python validate_pack.py --pack cloudflare/waf-rules/block_sqli.json
  python validate_pack.py --all
  python validate_pack.py --all --verbose
        """,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pack", help="Path to a single pack JSON file to validate")
    group.add_argument("--all", action="store_true", help="Validate all pack JSON files in the repository")
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print detailed output including quality warnings for valid packs",
    )
    args = parser.parse_args()

    # Load schema once for all validations
    schema = load_schema()
    if schema is None:
        print("WARNING: Schema file not found at expected path. Running field-level checks only.", file=sys.stderr)
    elif not JSONSCHEMA_AVAILABLE:
        print("WARNING: jsonschema not installed. Running field-level checks only. Run: pip install jsonschema", file=sys.stderr)

    if args.pack:
        # --- Single pack validation ---
        pack_path = Path(args.pack)
        if not pack_path.exists():
            print(f"ERROR: File not found: {pack_path}", file=sys.stderr)
            sys.exit(1)

        if is_template_pack_file(pack_path):
            print(f"SKIP  {pack_path}")
            sys.exit(0)
        errors = validate_pack(pack_path, schema=schema, verbose=args.verbose)
        if errors is None:
            print(f"SKIP  {pack_path}")
            sys.exit(0)
        if errors:
            print(f"FAIL  {pack_path}")
            for e in errors:
                print(f"  - {e}")
            sys.exit(1)
        else:
            print(f"OK    {pack_path}")

    elif args.all:
        # --- Validate all pack files in the repository ---
        # Find the repo root (3 levels up from this script: validators/ -> shared/ -> repo root)
        repo_root = Path(__file__).parent.parent.parent

        # Find all JSON files recursively, excluding schema/terraform/examples directories
        all_json_files = list(repo_root.rglob("*.json"))
        pack_files = [f for f in all_json_files if not should_skip(f)]

        if not pack_files:
            print("No pack files found to validate.", file=sys.stderr)
            sys.exit(0)

        failed = 0
        skipped = 0
        passed = 0

        for pf in sorted(pack_files):
            if is_template_pack_file(pf):
                skipped += 1
                continue
            errors = validate_pack(pf, schema=schema, verbose=args.verbose)
            if errors:
                print(f"FAIL  {pf.relative_to(repo_root)}")
                for e in errors:
                    print(f"  - {e}")
                failed += 1
            else:
                if args.verbose:
                    print(f"OK    {pf.relative_to(repo_root)}")
                else:
                    print(f"OK    {pf.relative_to(repo_root)}")
                passed += 1

        total = passed + failed
        print(f"\nResults: {passed}/{total} packs valid | {failed} failed | {skipped} skipped")

        if failed:
            sys.exit(1)


if __name__ == "__main__":
    main()
