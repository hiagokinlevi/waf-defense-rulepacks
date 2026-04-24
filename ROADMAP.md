# Roadmap

This document outlines the planned evolution of waf-defense-rulepacks. Items are grouped by phase and are subject to change based on community feedback.

---

## Phase 1 — Bootstrap (Current)

**Goal**: Establish the foundation — schema, validator, and high-quality packs for the two most common vendors (Cloudflare and AWS WAF).

- [x] Pack metadata JSON Schema (`shared/schemas/pack_metadata.json`)
- [x] Python pack validator (`shared/validators/validate_pack.py`)
- [x] Cloudflare: SQLi protection pack
- [x] Cloudflare: XSS protection pack
- [x] Cloudflare: Admin panel protection pack
- [x] Cloudflare: Login rate limit rule
- [x] Cloudflare: API rate limit template
- [x] Cloudflare: Bot mitigation baseline
- [x] Cloudflare: Security headers baseline (Transform Rules)
- [x] Cloudflare: Terraform module
- [x] AWS WAF: Managed rule groups WebACL
- [x] AWS WAF: Custom login rate limit rule
- [x] AWS WAF: Terraform module
- [x] Azure WAF: Front Door policy template
- [x] Azure WAF: Application Gateway policy template
- [x] Deployment guides (Cloudflare, AWS WAF)
- [x] Pre-production review checklist

---

## Phase 2 — Expand Coverage

**Goal**: Cover additional attack classes and add F5 / Imperva vendor support.

- [x] Cloudflare: Local File Inclusion (LFI) pack
- [x] Cloudflare: Remote File Inclusion (RFI) pack
- [x] Cloudflare: Command injection pack
- [x] Cloudflare: SSRF protection pack
- [x] Cloudflare: API abuse / excessive data exposure pack
- [x] Host header poisoning / routing override analysis pack
- [x] AWS WAF: IP reputation rule (using AWS Managed IP reputation list)
- [x] AWS WAF: Log4Shell virtual patch pack
- [x] F5 BIG-IP: iRules for SQLi and XSS
- [x] F5 BIG-IP: ASM policy export template
- [x] Imperva: Custom rule JSON templates
- [x] FortiWeb: P

## Automated Completions
- [x] Add Cloudflare JWT Authorization Header Enforcement Pack (cycle 34)
