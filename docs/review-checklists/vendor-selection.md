# Vendor Selection Checklist

Use this checklist when choosing or reviewing a WAF platform for a real environment. The goal is not to declare a single "best" WAF, but to verify that the selected platform matches the application, the operating model, and the team's maturity.

## 1. Platform Fit

- Is the workload internet-facing, internal, partner-facing, or mixed?
- Does the platform protect web apps, APIs, GraphQL, and webhook traffic in the way the application actually behaves?
- Does the team need global edge enforcement, origin-local enforcement, or both?
- Is Kubernetes / ingress support required?
- Does the platform fit the current cloud, network, or ADC architecture?

## 2. Rule and Policy Model

- Can the WAF express the controls we need for SQLi, XSS, SSRF, path traversal, sensitive routes, and authentication abuse?
- Does it support rate limiting for login, MFA, token issuance, and API-heavy endpoints?
- Are bot controls built in, or do they require an additional product?
- Can the team run rules in log, count, challenge, or block modes?
- Are exceptions and allowlists manageable without creating hidden risk?

## 3. API and Automation Readiness

- Can policies be versioned in Git and deployed through Terraform, API, or CI/CD?
- Is there enough structure to review changes before rollout?
- Can the team validate packs and templates before production deployment?
- Is rule promotion between environments practical?

## 4. Observability

- Does the platform emit logs rich enough for tuning?
- Can we see matched rule name, action, URI, source, and headers summary?
- Can events be sent to SIEM, cloud logging, or data lake tooling?
- Are dashboards or built-in analytics good enough for first-line operations?

## 5. Operational Tuning

- How easy is it to isolate a false positive to one path, hostname, or endpoint family?
- Can we scope rules by app, hostname, path, method, or header?
- Is there a clean rollback path if a rule causes business impact?
- Are staged rollouts supported?

## 6. Security Team Workflow

- Who will own rule creation, validation, and exception review?
- How often will rules and managed signatures be reviewed?
- Is there a process for monthly or quarterly posture review?
- Does the team have enough experience to operate an appliance-style WAF, or is a managed platform a better fit?

## 7. Risk Review

- What business-critical routes would be affected first by a false positive?
- Which apps need stricter baselines because they expose admin or financial workflows?
- Are there environments where challenge or block modes are not acceptable?
- Are internal or partner integrations likely to require carefully governed exceptions?

## 8. Decision Output

Before the selection is considered complete, the team should be able to document:

- chosen WAF type;
- chosen product or platform;
- target workloads;
- baseline rule categories to deploy first;
- known exclusions or constraints;
- logging and monitoring path;
- owner team and review cadence;
- rollout order: dev, staging, production.
