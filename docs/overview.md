# Overview

## What Is waf-defense-rulepacks?

`waf-defense-rulepacks` is a practitioner-maintained library of Web Application Firewall (WAF) rule packs. Each pack is a structured JSON document that bundles a WAF rule expression (in vendor-specific syntax) with metadata that makes it safe and practical to deploy.

## Why This Exists

WAF rules are easy to write incorrectly. Common problems include:

- **False positives**: Rules that block legitimate traffic because the expression is too broad
- **Undocumented side effects**: No guidance on which application endpoints will be affected
- **Deploy-and-forget**: Rules deployed in block mode without a validation period
- **No tuning guidance**: No direction on how to adapt rules to a specific application stack
- **No monitoring guidance**: No indication of what metrics to watch after deployment

This library addresses all of these by requiring every pack to document: `objective`, `risk_mitigated`, `potential_side_effects`, `tuning_notes`, `deployment_notes`, and `monitoring_notes`.

## Design Principles

### 1. Document Everything
Every pack must be self-contained documentation. A security engineer reading a pack for the first time should understand exactly what it does, what it protects against, and what could go wrong.

### 2. Log Before Block
The default stance is: deploy in log/count mode first, validate for 72+ hours, then switch to block. This is enforced culturally (deployment_notes field) not technically, but it is the expected practice.

### 3. Schema-First
All packs conform to a JSON Schema (`shared/schemas/pack_metadata.json`). The Python validator (`shared/validators/validate_pack.py`) enforces this in CI.

### 4. Vendor-Specific, Not Vendor-Locked
Packs are vendor-specific (a Cloudflare pack uses Cloudflare expression language) but the metadata schema is vendor-agnostic. This means packs across vendors can be compared and the library can eventually support cross-vendor compilation.

### 5. Defense Only
All content in this repository is strictly for defensive purposes: protecting systems you own or have explicit authorization to protect.

## Architecture

```
waf-defense-rulepacks/
├── {vendor}/                  # One directory per WAF vendor
│   ├── waf-rules/             # Core WAF rules (SQLi, XSS, RFI, etc.)
│   ├── rate-limits/           # Rate limiting rules
│   ├── bot-rules/             # Bot mitigation rules
│   ├── headers/               # Security header rules
│   ├── terraform/             # Infrastructure-as-code for this vendor
│   └── examples/              # Real-world usage examples
├── shared/
│   ├── schemas/               # JSON Schema for pack validation
│   └── validators/            # Python validator script
├── policies/                  # Composed policy packs (reference multiple packs)
├── docs/                      # This documentation
└── training/                  # Tutorials and labs
```

## Pack Lifecycle

```
draft → reviewed → tested → operational → mature
```

- **draft**: Initial submission, not yet peer-reviewed
- **reviewed**: Peer-reviewed for correctness and documentation quality
- **tested**: Tested against real traffic in a staging environment
- **operational**: Deployed in production by at least one team
- **mature**: Battle-tested with documented false positive patterns and tuning

## Getting Started

See the [README](../README.md) for a quick start guide.

For vendor-specific deployment, see:
- [Cloudflare Deployment Guide](deployment-guides/cloudflare.md)
- [AWS WAF Deployment Guide](deployment-guides/aws_waf.md)

AWS WAF teams that do not need the full baseline WebACL can start with the
standalone managed-rule packs under `aws-waf/rules/`, including the IP
reputation pack that ships in Count mode for sampled-request review.
