# waf-defense-rulepacks

[![License: CC%20BY%204.0](https://img.shields.io/badge/License-CC%20BY%204.0-yellow.svg)](LICENSE)
[![Status: Active Development](https://img.shields.io/badge/Status-Active%20Development-blue.svg)]()
[![Platforms: 10](https://img.shields.io/badge/Platforms-10-green.svg)]()
[![Packs: Growing](https://img.shields.io/badge/Packs-Growing-orange.svg)]()

> A library of reusable, well-documented defensive WAF rule packs for Cloudflare, AWS WAF, Azure WAF, F5, FortiWeb, Imperva, and Check Point. Each pack ships with metadata, deployment notes, tuning guidance, and Terraform examples.

---

## What Is This?

`waf-defense-rulepacks` is a curated collection of Web Application Firewall (WAF) rule packs designed to accelerate secure deployments across multiple WAF vendors. Rather than writing WAF rules from scratch for every project, this library provides ready-to-use, peer-reviewed packs with:

- Clear **objective** and **risk mitigated** statements
- **Severity** and **maturity** classifications
- **Tuning notes** to reduce false positives
- **Deployment notes** (start in log mode, validate, then block)
- **Monitoring guidance** so you know what to watch after deploying
- **Terraform modules** for infrastructure-as-code deployment

This is not a product — it is a practitioner's toolkit. Packs should always be reviewed and tested in your specific environment before production use.

---

## Supported Vendors

| Vendor | Coverage |
|---|---|
| **Cloudflare** | WAF rules, rate limits, bot rules, security headers, Transform Rules, Terraform |
| **AWS WAF** | WebACL with managed rule groups, standalone IP reputation and Log4Shell packs, custom rules, Terraform |
| **Azure WAF** | Front Door policy, Application Gateway policy |
| **F5 BIG-IP** | SQLi and XSS iRule starter packs for enterprise ADC workflows |
| **FortiWeb** | Path traversal signature baseline for policy-package rollouts |
| **Imperva** | API authentication brute-force custom rule template |
| **Check Point** | Administrative surface restriction policy baseline |
| **ModSecurity** | Export tooling for reusable rate-limit stubs |
| **NGINX** | Export tooling for reusable rate-limit stubs |
| **Generic** | Shared metadata schema, cataloging, and vendor-agnostic planning |

---

## Pack Structure

Every pack is a JSON file with a standard set of metadata fields:

```jsonc
{
  "name": "Human-readable name",
  "vendor": "cloudflare | aws-waf | azure-waf | ...",
  "category": "sqli_protection | xss_protection | rate_limiting | ...",
  "app_context": "generic | saas | api | e-commerce | ...",
  "objective": "What the rule does",
  "risk_mitigated": "What attack or risk it addresses",
  "severity": "critical | high | medium | low | informational",
  "mode": "block | log | challenge | count",
  "recommended_for": ["web_apps", "apis", "admin_panels"],
  "potential_side_effects": "Known false positive scenarios",
  "tuning_notes": "How to adjust for your environment",
  "deployment_notes": "Pre-production recommendations",
  "monitoring_notes": "What to observe after deployment",
  "version": "semver string",
  "maturity": "draft | reviewed | tested | operational | mature",
  // vendor-specific fields follow...
}
```

The full JSON Schema is at [`shared/schemas/pack_metadata.json`](shared/schemas/pack_metadata.json).

---

## Quick Start

### 1. Browse available packs

```
waf-defense-rulepacks/
├── cloudflare/
│   ├── waf-rules/        # Custom WAF rule expressions
│   ├── rate-limits/      # Rate limiting rules
│   ├── bot-rules/        # Bot mitigation rules
│   ├── headers/          # Security header enforcement (Transform Rules)
│   └── terraform/        # Terraform modules for Cloudflare
├── aws-waf/
│   ├── managed_rule_groups.json
│   ├── custom_rules.json
│   └── terraform/
├── azure-waf/
│   ├── front_door_policy.json
│   ├── app_gateway_policy.json
│   └── custom-rules/
├── checkpoint/
│   └── policies/
├── f5/
│   └── irules/
├── fortiweb/
│   └── signatures/
├── generic/
│   └── rules/
├── imperva/
│   └── custom-rules/
├── modsecurity/
│   └── rules/
├── nginx/
│   └── rules/
├── shared/
│   ├── schemas/          # JSON Schema for pack validation
│   └── validators/       # Validation and catalog helpers
├── policies/             # High-level YAML policy packs
├── docs/                 # Deployment guides and checklists
└── training/             # Tutorials and labs
```

### 2. Create an isolated environment and install the toolkit

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

If you are working in a restricted or offline environment that already has the
runtime dependencies and build backend (`setuptools` + `wheel`) available,
install without build isolation:

```bash
python -m pip install --no-build-isolation --no-deps -e .
```

On Python 3.12+ and 3.13 virtualenvs, install from an environment where
`setuptools` is already present, or create the venv with access to the local
site packages before using `--no-build-isolation`.

### 3. Pick a pack and review it

```bash
cat cloudflare/waf-rules/block_sqli.json
```

Review the `potential_side_effects` and `tuning_notes` fields. Understand what the rule does before deploying it.

### 4. Deploy in log mode first

Every pack includes a `deployment_notes` field recommending a log-only period (typically 72 hours) before switching to block mode. This is strongly recommended.

### 5. Validate packs

```bash
python shared/validators/validate_pack.py --all
pytest -q
```

### 6. Map coverage before you deploy

```bash
waf-catalog --repo-root . --format summary
waf-catalog --repo-root . --format markdown --output reports/catalog.md
```

This gives you a quick inventory of coverage by vendor, category, and maturity before you decide what to deploy or expand next.

### 7. Evaluate higher-risk request patterns locally

The repository also ships Python-based defensive analyzers for classes that are
hard to express cleanly in vendor JSON alone. For example, the host header pack
detects routing override and poisoning attempts before deployment:

```bash
python - <<'PY'
from shared.rulepacks.host_header_attack_pack import HostHeaderAttackPack, HostHeaderRequest

result = HostHeaderAttackPack().evaluate(
    HostHeaderRequest(
        url="https://app.example.com/login",
        headers={"Host": "localhost", "X-Forwarded-Host": "evil.example.net"},
    )
)
print(result.summary())
PY
```

---

## How to Use a Pack

### Cloudflare (manual)

1. Copy the `cloudflare_expression` from a pack JSON.
2. Go to Cloudflare Dashboard > Security > WAF > Custom Rules.
3. Create a new rule, paste the expression, and set Action to **Log** initially.
4. Monitor for 72 hours, then switch to **Block** if no false positives.

### Cloudflare (Terraform)

```hcl
module "waf_sqli_protection" {
  source  = "./cloudflare/terraform"
  zone_id = var.zone_id
  mode    = "log"  # Start in log mode
}
```

See [`cloudflare/terraform/main.tf`](cloudflare/terraform/main.tf) for the full module.

### AWS WAF

```bash
aws wafv2 create-web-acl --cli-input-json file://aws-waf/managed_rule_groups.json
```

See [`docs/deployment-guides/aws_waf.md`](docs/deployment-guides/aws_waf.md) for step-by-step instructions.

The standalone AWS IP reputation pack is available at
[`aws-waf/rules/ip_reputation_managed_group.json`](aws-waf/rules/ip_reputation_managed_group.json).
It starts in `Count` mode and documents the transition to enforcement after
sampled-request review.

---

## Validating Packs

The repository includes a Python validator that checks all pack JSON files against the schema:

```bash
# Validate a single pack
python shared/validators/validate_pack.py --pack cloudflare/waf-rules/block_sqli.json

# Validate all packs
python shared/validators/validate_pack.py --all
```

The host header attack detector is available at [`shared/rulepacks/host_header_attack_pack.py`](shared/rulepacks/host_header_attack_pack.py) and covers:

- conflicting host-routing headers across proxies and origin layers
- absolute-URL host values and invalid path-bearing host headers
- internal, loopback, and cloud metadata targets
- external-domain mismatches between `Host` and forwarding headers
- IP-literal overrides against canonical domain-based routing

The Cloudflare RFI pack is available at [`cloudflare/waf-rules/block_remote_file_inclusion.json`](cloudflare/waf-rules/block_remote_file_inclusion.json) and blocks file-loading parameters that point to external HTTP, HTTPS, FTP, protocol-relative, or percent-encoded remote resources. Deploy it in log mode first on CMS, import, and template-rendering paths before enabling block mode.

Use [`docs/waf-landscape.md`](docs/waf-landscape.md) to compare WAF platform types and [`docs/review-checklists/vendor-selection.md`](docs/review-checklists/vendor-selection.md) to structure product selection and rollout decisions.

---

## Ethical Use and Limitations

- These packs are designed exclusively for **defensive purposes**: protecting systems you own or have explicit authorization to protect.
- WAF rules are not a substitute for secure application development. They are a defense-in-depth layer.
- All packs should be **tested in a non-production environment** before deployment.
- False positives are possible. Always start in log/count mode and tune before blocking.
- This repository does not provide support for offensive use of any content herein.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities in this project.

## License

[CC BY 4.0](LICENSE) — see the file for details.
