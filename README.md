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
| **AWS WAF** | WebACL with managed rule groups, standalone IP reputation and Log4Shell packs, SQLi URI/query virtual patch pack, custom rules, Terraform |
| **Azure WAF** | Front Door policy, Application Gateway policy |
| **F5 BIG-IP** | SQLi and XSS iRule starter packs plus an ASM policy export template for enterprise ADC workflows |
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
  "vendor": "cloudflare | aws-waf | azure-waf
```
