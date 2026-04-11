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
- [ ] F5 BIG-IP: ASM policy export template
- [x] Imperva: Custom rule JSON templates
- [x] FortiWeb: Path traversal signature baseline
- [x] Check Point: Administrative surface restriction baseline
- [ ] Deployment guide: Azure WAF
- [ ] Deployment guide: F5

---

## Phase 3 — Policy Packs and Automation

**Goal**: Compose individual rules into higher-level policy packs and add CI/CD automation.

- [ ] Policy pack: `baseline_web_app` — composite pack with recommended baseline for generic web apps
- [ ] Policy pack: `saas_api_protection` — composite pack for SaaS API endpoints
- [ ] Policy pack: `e_commerce_baseline` — composite pack targeting e-commerce attack surfaces
- [ ] GitHub Actions CI workflow: validate all packs on PR
- [ ] Automated maturity promotion: `draft` → `reviewed` via PR review checklist
- [ ] SARIF output from validator for GitHub Security tab integration
- [x] CLI catalog: inventory packs by vendor, category, and maturity

---

## Phase 4 — Multi-Vendor Normalization

**Goal**: Provide a vendor-agnostic rule format that can be compiled to vendor-specific expressions.

- [ ] Design vendor-agnostic pack format (`shared/formats/generic_rule.json`)
- [ ] Cloudflare compiler: generic → Cloudflare expression
- [ ] AWS WAF compiler: generic → AWS WAF statement JSON
- [ ] Azure WAF compiler: generic → Azure WAF custom rule
- [ ] CLI tool: `waf-pack-compiler`

---

## Ideas / Backlog

- FortiWeb support
- Check Point CloudGuard support
- Modsecurity / OWASP CRS integration guide
- Pack versioning and changelog automation
- Community voting on maturity promotion
- Integration with MITRE ATT&CK for Enterprise (web application techniques)

---

Have an idea or request? Open an issue with the label `roadmap`.
