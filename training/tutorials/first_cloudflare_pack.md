# Tutorial: Deploying Your First Cloudflare WAF Pack

This hands-on tutorial walks through deploying the `block_sqli.json` pack to a Cloudflare zone, from zero to a validated, block-mode deployment. Estimated time: 30-45 minutes.

## What You Will Learn

- How to read and understand a k1N WAF pack
- How to deploy a WAF rule in log mode using Cloudflare Dashboard
- How to validate the rule using Cloudflare Security Events
- How to identify and add exclusions for false positives
- How to safely switch to block mode

## Prerequisites

- A Cloudflare account with at least one active zone (domain)
- A web application behind Cloudflare (can be a test application)
- Cloudflare plan: Free or above (custom WAF rules are available on all plans)

---

## Part 1: Read the Pack

Before deploying any rule, read the full pack documentation.

```bash
cat cloudflare/waf-rules/block_sqli.json
```

Read these fields carefully:

**`objective`**: Understand what the rule is trying to detect. For `block_sqli.json`:
> "Detect and block common SQL injection patterns in query strings, path segments, and request bodies"

**`potential_side_effects`**: Know what could go wrong. For `block_sqli.json`:
> "May produce false positives on applications that accept SQL-like syntax in legitimate inputs (e.g., search boxes). Test in log-only mode first."

**`cloudflare_expression`**: This is the actual Cloudflare firewall rule expression you will deploy:
```
(http.request.uri.query contains "' OR" or http.request.uri.query contains "1=1" or http.request.uri.query contains "UNION SELECT" ...)
```

**`deployment_notes`**:
> "Deploy in 'log' mode for a minimum of 72 hours before switching to 'block'."

This is the most important field. **Never skip the log mode validation period.**

---

## Part 2: Deploy in Log Mode

### Step 1: Navigate to Custom Rules

1. Log in to [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Click on your zone (domain)
3. Go to **Security** in the left navigation
4. Click **WAF**
5. Select the **Custom rules** tab
6. Click **Create rule**

### Step 2: Configure the Rule

Fill in the form:

- **Rule name**: `k1N SQLi Protection v1.0`
- **When incoming requests match...**: Click **Edit expression**
- Paste the `cloudflare_expression` from the pack:
  ```
  (http.request.uri.query contains "' OR" or http.request.uri.query contains "1=1" or http.request.uri.query contains "UNION SELECT" or http.request.uri.query contains "--" or http.request.body contains "' OR" or http.request.body contains "UNION SELECT")
  ```
- **Then take action**: Select **Log**

Click **Deploy**.

**Verify** the rule appears in the custom rules list with the Log action badge.

---

## Part 3: Monitor in Log Mode

Wait at least 72 hours. Then review the events:

### Step 1: Access Security Events

1. Go to **Security** > **Events**
2. Set the time range to the last 72 hours
3. Filter by **Service** = **Custom rules**
4. Filter by **Rule** = `k1N SQLi Protection v1.0`

### Step 2: Analyze Each Event

For each event, review:

| Field | What to check |
|---|---|
| **URI Path** | Is this a legitimate endpoint? (e.g., `/api/search`) |
| **Query string** | Does it contain an actual SQL injection attempt, or legitimate data? |
| **Source IP** | Known scanner, bot, or legitimate user? |
| **User-Agent** | Scanner tool or legitimate browser? |
| **Country** | Expected country for your users? |

### Determining True Positive vs False Positive

**True positive (keep blocking)**: A request from an unknown IP with a user agent like `sqlmap/1.7.8#stable` containing `UNION SELECT` in the query string. This is an active SQL injection scan.

**False positive (needs exclusion)**: A request from a logged-in user to `/api/search?q=Select+all+items` — a legitimate search query that happens to contain "SELECT".

---

## Part 4: Add Exclusions (If Needed)

If you found false positives, add exclusions before switching to block mode.

### Example: Search Endpoint Exclusion

If `/api/search` is generating false positives, modify the expression to exclude it:

```
(
  http.request.uri.query contains "UNION SELECT" or
  http.request.body contains "UNION SELECT"
) and not http.request.uri.path contains "/api/search"
```

Update the rule expression in the dashboard and click **Save**.

Wait another 24 hours to confirm the exclusion resolves the false positives.

---

## Part 5: Switch to Block Mode

When satisfied that no legitimate traffic is being matched:

1. Edit the rule in the Cloudflare Dashboard
2. Change the action from **Log** to **Block**
3. Click **Deploy**

### Immediately After Switching

Monitor the **Security** > **Events** log for the next 30 minutes. A block event spike is normal if active scanners are hitting your application. What to look for:

- Blocks from expected scanner IP ranges (security tools, Cloudflare threat intel): **Normal**
- Blocks from your users' IP ranges or known CDN/proxy ranges: **Investigate immediately**

If you see unexpected blocks, switch back to log mode immediately:
1. Edit the rule
2. Change action back to **Log**
3. Investigate the blocked requests
4. Add necessary exclusions before re-enabling block mode

---

## Summary

You have successfully:
1. Read and understood a k1N WAF pack
2. Deployed a SQLi protection rule in log mode
3. Validated it for 72 hours by reviewing events
4. Added exclusions for any false positives
5. Switched to block mode safely

Next steps:
- Deploy `block_xss.json` using the same process
- Deploy `protect_admin_panel.json` (this one can go straight to block mode if your IP allowlist is accurate)
- Read the [full Cloudflare Deployment Guide](../docs/deployment-guides/cloudflare.md) for the complete baseline deployment workflow
- Continue with [`cloudflare/examples/protect_public_api.md`](../../cloudflare/examples/protect_public_api.md) and [`training/tutorials/cloudflare_zero_downtime_rollout.md`](cloudflare_zero_downtime_rollout.md) for larger API-heavy estates
