# WAF Landscape

This guide maps the major types of WAF platforms that security teams encounter in real programs. The goal is to help practitioners choose the right control surface, understand operational tradeoffs, and avoid treating every WAF as if it behaved the same way.

## Main WAF Platform Types

| WAF type | Typical products | Best fit | Operational strengths | Common tradeoffs |
|---|---|---|---|---|
| Edge / CDN WAF | Cloudflare, Akamai App & API Protector, Fastly Next-Gen WAF | Internet-facing sites, APIs, global traffic, DDoS-adjacent use cases | Fast rollout, global visibility, bot controls, rate limiting, response header enforcement | Less application context than origin-aware controls, vendor-specific expression languages |
| Cloud-native managed WAF | AWS WAF, Azure WAF, Google Cloud Armor | Workloads already anchored to one cloud provider | Native integration with load balancers, API gateways, logging, IAM, and IaC | Coverage and syntax vary between providers; portability is limited |
| ADC / appliance WAF | F5 BIG-IP ASM / Advanced WAF, Imperva, FortiWeb, Check Point, Barracuda | Enterprises with complex internal apps, layered segmentation, and established appliance operations | Deep policy control, mature enterprise workflows, strong integration with legacy estates | Heavier operational footprint, more manual tuning, slower change cadence |
| Open-source / ingress WAF | ModSecurity + OWASP CRS, NGINX App Protect, ingress-controller add-ons, open-appsec | Kubernetes, self-managed reverse proxies, mixed environments | Flexible, transparent, easier to extend and inspect | Requires stronger in-house ownership for updates, tuning, and observability |
| API security / WAAP-adjacent controls | API gateways with schema validation, bot products, abuse protection layers | High-volume APIs, partner integrations, GraphQL, mobile backends | Rich API-aware controls, token and quota context, schema-level enforcement | Usually complements a WAF rather than replacing one |

## How Professionals Usually Combine Them

### 1. Edge WAF + Origin Controls

This is the most common modern pattern:

- edge WAF for broad attack filtering, bot mitigation, and rate limiting;
- cloud or appliance WAF for application-aware custom policies;
- application telemetry for final validation and tuning.

### 2. Cloud-native WAF + API Gateway

This pattern works well when teams already standardize on managed cloud services:

- managed WAF for baseline protections;
- API gateway for quotas, auth-aware throttling, and request validation;
- cloud logging for operational review and alerting.

### 3. Appliance WAF + Strict Change Control

This is common in regulated enterprises:

- appliance WAF enforces enterprise policy baselines;
- change windows and approvals reduce rollout risk;
- compensating controls and exception registers become essential.

### 4. Open-source WAF + Platform Engineering

This suits platform teams that want portable controls:

- ModSecurity or NGINX-based controls provide transparent, code-reviewed policy;
- GitOps and CI validation become critical;
- teams need explicit ownership for CRS updates and false-positive tuning.

## Selection Model

Choose a WAF family based on the operating model first, not the marketing label.

### Use Edge / CDN WAF when

- the application is public and latency-sensitive;
- you need global rate limiting or bot scoring quickly;
- the security team wants simple rollout through dashboard or Terraform.

### Use Cloud-native managed WAF when

- the workload already lives behind provider-native load balancing;
- operations are centered on AWS, Azure, or GCP;
- the team wants IAM, logging, and deployment patterns to stay cloud-local.

### Use ADC / appliance WAF when

- the estate includes internal apps, legacy apps, or network segmentation dependencies;
- the organization already operates F5, Imperva, FortiWeb, or Check Point professionally;
- deeper custom policy control matters more than speed of rollout.

### Use Open-source / ingress WAF when

- you need portable controls across mixed environments;
- platform teams are comfortable reviewing and tuning rules as code;
- transparency and inspectability matter more than managed convenience.

## Professional Operating Checklist

Regardless of vendor, strong WAF programs usually share the same habits:

1. Asset classification first:
   identify public apps, admin surfaces, partner APIs, GraphQL endpoints, and webhook receivers.
2. Baseline packs before bespoke rules:
   start with well-understood protections for SQLi, XSS, path traversal, SSRF, authentication abuse, and sensitive routes.
3. Log or count before block:
   validate on real traffic before enforcing.
4. Exception governance:
   document why a bypass exists, who owns it, and when it must be reviewed again.
5. Tuning with evidence:
   every suppression should reference observed false positives, not intuition alone.
6. Coverage review:
   track vendors, categories, and maturity so gaps stay visible.
7. Monitoring and rollback:
   define what success and regression look like before enabling a pack.

## Tooling and Rule Strategy

This repository is organized to help teams work across all of these platform types:

- vendor-specific rule packs for direct deployment;
- Python utilities for validation and coverage analysis;
- export tooling for reusable rate-limit patterns;
- review checklists for vendor selection and pre-production rollout;
- multivendor documentation so security teams can compare control surfaces without starting from zero.

## Recommended Reading in This Repository

- [`docs/overview.md`](overview.md)
- [`docs/review-checklists/pre_production.md`](review-checklists/pre_production.md)
- [`docs/review-checklists/vendor-selection.md`](review-checklists/vendor-selection.md)
- [`shared/validators/coverage_analyzer.py`](../shared/validators/coverage_analyzer.py)
- [`shared/validators/pack_catalog.py`](../shared/validators/pack_catalog.py)
