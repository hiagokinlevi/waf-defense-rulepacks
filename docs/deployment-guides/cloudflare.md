# Cloudflare WAF Deployment Guide

This guide walks through deploying waf-defense-rulepacks rules to a Cloudflare zone, either manually via the dashboard or using Terraform.

## Prerequisites

- A Cloudflare account with an active zone (domain)
- Plan requirements:
  - Custom WAF rules: Free plan and above
  - Rate limiting rules: Pro plan and above
  - Bot Management (bot score): Pro plan minimum (limited), Enterprise for full Bot Management
  - Transform Rules (security headers): Free plan and above

## Deployment Workflow

```
Review pack → Deploy in Log mode → Validate (72h) → Switch to Block → Monitor
```

**Never deploy in Block mode without first validating in Log mode.**

---

## Method 1: Manual via Cloudflare Dashboard

### Step 1: Access WAF Custom Rules

1. Log in to Cloudflare Dashboard
2. Select your zone
3. Navigate to **Security** > **WAF** > **Custom rules**
4. Click **Create rule**

### Step 2: Deploy SQLi Protection

From `cloudflare/waf-rules/block_sqli.json`, copy the `cloudflare_expression` field.

- **Rule name**: `SQLi Protection v1.0`
- **Expression**: paste the expression
- **Action**: **Log** (not Block — start in log mode)
- **Status**: Enabled

Click **Deploy**.

### Step 3: Monitor in Log Mode

In Cloudflare Dashboard:
1. Go to **Security** > **Events**
2. Filter by Rule ID (find your rule name)
3. Review the blocked requests for false positives
4. Check request URI paths, query strings, and body content

Wait **at least 72 hours** before proceeding.

### Step 3a: Deploy API abuse / excessive data exposure coverage

Use [`cloudflare/waf-rules/block_api_abuse_excessive_data_exposure.json`](../../cloudflare/waf-rules/block_api_abuse_excessive_data_exposure.json) when you need defensive coverage for:

- bulk field expansion such as `fields=*`, `include=*`, and `expand=*`
- suspicious export-style paths like `/export`, `/dump`, and `/backup`
- aggressive pagination hints such as `limit=1000` or `offset=10000`
- GraphQL introspection probes on `/graphql`

Recommended rollout:

1. Start in **Log** mode on internet-facing APIs and partner endpoints.
2. Review events for legitimate analytics jobs, BI exports, and staging GraphQL tooling.
3. Add scoped exclusions for known-safe automation before moving to **Block**.
4. Keep separate handling for staging and production if your engineering team still depends on schema introspection outside production.

### Step 4: Switch to Block Mode

If no false positives were observed:
1. Edit the rule
2. Change Action from **Log** to **Block**
3. Save

If false positives were observed, add path-based exclusions before switching:

```
# Example: exclude /api/search from SQLi checking
(
  http.request.uri.query contains "UNION SELECT" or
  http.request.body contains "UNION SELECT"
) and not http.request.uri.path contains "/api/search"
```

---

## Method 2: Terraform

See `cloudflare/terraform/main.tf` for the full Terraform module.

### Quick Start

```bash
# 1. Install Terraform (>= 1.5)
brew install terraform

# 2. Set Cloudflare API token
export CLOUDFLARE_API_TOKEN="your-api-token-with-zone-waf-permissions"

# 3. Get your Zone ID from Cloudflare Dashboard > Overview > Zone ID

# 4. Initialize Terraform
cd cloudflare/terraform
terraform init

# 5. Plan in log mode
terraform plan \
  -var="zone_id=your-zone-id" \
  -var="mode=log"

# 6. Apply in log mode
terraform apply \
  -var="zone_id=your-zone-id" \
  -var="mode=log"

# 7. After 72h validation, switch to block mode
terraform apply \
  -var="zone_id=your-zone-id" \
  -var="mode=block"
```

### Cloudflare API Token Permissions

Create an API token at `https://dash.cloudflare.com/profile/api-tokens` with:
- Zone > WAF > Edit
- Zone > Zone > Read (to read zone settings)

---

## Deploying Rate Limit Rules

Rate limit rules are separate from WAF Custom rules in Cloudflare.

1. Go to **Security** > **WAF** > **Rate limiting rules**
2. Click **Create rule**
3. Use the configuration from `cloudflare/rate-limits/login_rate_limit.json`

Key settings:
- **Expression**: `(http.request.method eq "POST" and http.request.uri.path contains "/login")`
- **Characteristic**: IP
- **Requests**: 5 per minute
- **Action**: Block (with 10-minute mitigation timeout)

---

## Deploying Security Headers (Transform Rules)

1. Go to **Rules** > **Transform Rules** > **HTTP Response Header Modification**
2. Click **Create rule**
3. Use the `cloudflare_transform_rule.response_headers` configuration from `cloudflare/headers/security_headers_baseline.json`
4. Set expression to `true` (apply to all responses)

---

## Monitoring After Deployment

1. **Cloudflare Security Events**: Security > Events > Filter by Action = Block
2. **Analytics**: Security > WAF > Overview (shows rule match counts over time)
3. **Notifications**: Set up Cloudflare notifications for:
   - Security Events spike threshold
   - Rate limit rule exceeded
4. **Logpush** (Enterprise): Push WAF events to your SIEM for long-term analysis

---

## Common Issues

### False Positives on Search Endpoints

**Symptom**: SQLi or XSS rule blocking requests to `/api/search` or similar endpoints.

**Fix**: Add a negative path condition to the rule expression:
```
<existing expression> and not http.request.uri.path contains "/api/search"
```

### API Abuse Pack Blocking Legitimate Export or GraphQL Tooling

**Symptom**: Export jobs, BI integrations, or developer schema tooling trigger the API abuse pack.

**Fix**: Keep the rule in log mode while you identify trusted paths, service tokens, or source IP ranges. Then add narrow exclusions for those workflows instead of weakening the global expression. In most environments, `/graphql` introspection should be treated differently in staging and production.

### Admin Panel Rule Blocking Legitimate Admins

**Symptom**: Admins cannot access `/admin` after deploying admin protection rule.

**Fix**: Update the IP allowlist in the rule expression to include all admin user IPs and VPN exit nodes. Do not remove the rule — scope it correctly.

### Rate Limit Blocking CI/CD Pipeline

**Symptom**: Integration tests that call `/login` are being rate limited.

**Fix**: Add the CI/CD runner IP(s) to a bypass list or use a dedicated test credential endpoint that is excluded from rate limiting.
