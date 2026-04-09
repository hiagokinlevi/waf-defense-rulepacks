# Example: Protecting a SaaS Application with Cloudflare WAF

This guide walks through how to apply waf-defense-rulepacks to a typical SaaS web application behind Cloudflare.

## Application Profile

- **Type**: Multi-tenant SaaS (REST API + React frontend)
- **Auth**: JWT tokens via `/api/auth/login` (POST)
- **Admin panel**: `/admin/*` (internal use only)
- **API**: `/api/v1/*` (authenticated clients), `/api/public/*` (unauthenticated)
- **Rich text editor**: `/api/v1/posts` (accepts HTML content)

---

## Step 1: Deploy Security Headers

Start here — security headers have the lowest risk of false positives.

```bash
# Navigate to Cloudflare Dashboard > your zone > Rules > Transform Rules > HTTP Response Header Modification
# Create a new rule using the config from:
cat cloudflare/headers/security_headers_baseline.json
```

Update the `Content-Security-Policy-Report-Only` directive to match your actual CDN and API domains.

**Expected result**: No user impact. Start collecting CSP reports for 2-4 weeks.

---

## Step 2: Deploy Admin Panel Protection

This is the highest-value, lowest-risk rule to deploy in block mode.

```bash
# Review the rule
cat cloudflare/waf-rules/protect_admin_panel.json
```

Before deploying, identify all IPs that access `/admin`:
- Office IPs and VPN exit nodes
- Internal CI/CD agents that run admin API calls
- Developer workstation IPs (if no VPN)

Update the expression with your IP ranges:

```
(http.request.uri.path wildcard "/admin*") and not ip.src in {1.2.3.4/32 5.6.7.8/29 10.0.0.0/8}
```

Deploy in **block** mode immediately — no log-mode period needed if your IP list is accurate.

---

## Step 3: Deploy Login Rate Limiting

```bash
cat cloudflare/rate-limits/login_rate_limit.json
```

For this SaaS application:
- Path: `/api/auth/login`
- Method: POST
- Threshold: 5 requests per IP per 60 seconds
- Action: Block for 10 minutes

Deploy in **log** mode for 24 hours first. Check that no legitimate automation (e.g., integration tests running in CI) is hitting the login endpoint at more than 5 req/min from a single IP.

---

## Step 4: Deploy SQLi and XSS Protection (with Exclusions)

```bash
cat cloudflare/waf-rules/block_sqli.json
cat cloudflare/waf-rules/block_xss.json
```

**Critical**: This SaaS application has a rich text editor at `/api/v1/posts` that accepts HTML. The XSS rule would block legitimate POST requests to this endpoint.

Add an exclusion:

```
# XSS rule expression with exclusion for the rich text editor endpoint
(
  http.request.uri.query contains "<script" or
  http.request.body contains "<script" or
  http.request.body contains "javascript:"
) and not (
  http.request.uri.path eq "/api/v1/posts" and http.request.method eq "POST"
)
```

Deploy SQLi and XSS rules in **log** mode for **72 hours** before switching to block.

---

## Step 5: Deploy API Rate Limiting

```bash
cat cloudflare/rate-limits/api_rate_limit.json
```

For this app:
- Unauthenticated `/api/public/*`: 60 req/min per IP
- Authenticated `/api/v1/*`: 300 req/min per JWT (or per IP if JWT-based characteristics are not available)

Deploy in **log** mode for one week. Review your API gateway metrics for p95 request rates per endpoint.

---

## Step 6: Enable Bot Mitigation

```bash
cat cloudflare/bot-rules/bot_mitigation_baseline.json
```

For API endpoints (`/api/*`), do **not** issue JS challenges (API clients cannot complete them). Apply bot mitigation only to web frontend paths.

```
# Apply bot challenge only to non-API paths
cf.bot_management.score lt 30 and not http.request.uri.path starts_with "/api/"
```

---

## Resulting Security Posture

After completing all steps, your SaaS application will have:

| Control | Status |
|---|---|
| Security headers (HSTS, XFO, XCTO, etc.) | Enforced |
| Admin panel IP restriction | Blocking |
| Login brute-force protection | Blocking |
| SQLi detection | Blocking |
| XSS detection (with editor exclusion) | Blocking |
| API rate limiting | Blocking |
| Bot mitigation (frontend only) | Challenging |

---

## Monitoring

After all rules are in block mode, set up the following Cloudflare notifications:
- Firewall event spike (> 2x baseline within 5 minutes)
- Rate limit threshold spike
- Bot score distribution shift

Review the Cloudflare Security Events log weekly for false positives or new attack patterns.
