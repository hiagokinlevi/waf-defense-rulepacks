# WAF Analysis Prompts

A collection of prompts for using AI assistants to assist with WAF analysis tasks. These are starting points — always review AI output critically and validate with your own environment knowledge.

---

## 1. False Positive Investigation

Use when a WAF rule is blocking requests that appear to be legitimate traffic.

```
I have a WAF rule that is generating false positives. Here is the rule expression:

[PASTE RULE EXPRESSION]

Here is a sample of the blocked requests (redact sensitive data):

[PASTE LOG ENTRIES]

The application context is: [DESCRIBE YOUR APP, e.g., "e-commerce platform, customers search for products using a /search endpoint that accepts user input"]

Please analyze:
1. Why is this rule triggering on these requests?
2. Which parts of the expression are causing the false positive?
3. What exclusions or adjustments would reduce false positives while maintaining detection coverage?
4. Are there alternative expression patterns that would be more precise?
```

---

## 2. Rule Expression Review

Use when writing a new WAF rule expression and wanting a second opinion.

```
Please review this WAF rule expression for a [VENDOR] WAF:

[PASTE EXPRESSION]

The objective is: [DESCRIBE WHAT YOU ARE TRYING TO BLOCK]

Please evaluate:
1. Does the expression achieve the stated objective?
2. Are there bypass techniques that would evade this expression?
3. What are the most likely false positive scenarios?
4. How could the expression be made more precise?
5. Are there any syntax errors or performance concerns?
```

---

## 3. Pack Selection for a New Application

Use when onboarding a new application to WAF protection.

```
I am deploying WAF protection for a new application with the following characteristics:

- Application type: [e.g., REST API for a mobile app, WordPress CMS, SaaS dashboard]
- Tech stack: [e.g., Python/Django, Node.js/Express, PHP/Laravel]
- Authentication: [e.g., JWT tokens, session cookies, API keys]
- Special considerations: [e.g., accepts file uploads, has a rich text editor, processes financial data]
- WAF vendor: [Cloudflare, AWS WAF, Azure WAF]

From the waf-defense-rulepacks library, which packs would you recommend deploying, in which order, and why? What are the highest-risk false positive scenarios I should watch for during the log mode validation period?
```

---

## 4. Post-Incident WAF Coverage Analysis

Use after a security incident to identify WAF coverage gaps.

```
We experienced a security incident with the following characteristics:

- Attack type: [e.g., SQL injection, credential stuffing, API scraping]
- Attack vector: [e.g., query string, POST body, specific endpoint]
- Detection: [how was it detected, and how long did it take]
- Impact: [what was the impact]

Our current WAF configuration is:
[PASTE OR DESCRIBE YOUR CURRENT WAF RULES]

Please analyze:
1. Should our existing WAF rules have detected this attack? Why or why not?
2. What WAF rules from waf-defense-rulepacks would have detected or blocked this attack?
3. Were there any bypass techniques used that our rules do not cover?
4. What additional defensive layers (beyond WAF) would help prevent similar incidents?
```

---

## 5. Rate Limit Threshold Calculation

Use when determining appropriate rate limits for your application.

```
I need to set rate limits for the following endpoint:

- Endpoint: [e.g., POST /api/auth/login]
- Normal usage pattern: [e.g., a user might attempt login 2-3 times if they mistype their password; max 5 attempts in a session]
- Peak legitimate traffic: [e.g., during business hours we see ~200 unique users logging in per minute across the application]
- Concern: [e.g., credential stuffing bots that try thousands of passwords per account]

Please suggest:
1. An appropriate rate limit threshold (requests per IP per minute)
2. The mitigation timeout (how long to block after limit is exceeded)
3. Whether to use IP-based or user-based rate limiting for this endpoint
4. Whether a block action or a challenge action is more appropriate
5. How to handle legitimate shared-IP scenarios (corporate NAT, university networks)
```

---

## 6. WAF Rule Documentation Review

Use when reviewing a draft WAF pack before submitting a pull request.

```
Please review this WAF pack for documentation quality and completeness:

[PASTE PACK JSON]

Please evaluate each field:
1. Is the 'objective' clear and accurate?
2. Is the 'risk_mitigated' specific enough to understand the attack being addressed?
3. Are the 'potential_side_effects' honest and comprehensive?
4. Are the 'tuning_notes' actionable?
5. Does the 'deployment_notes' field recommend starting in log mode?
6. Is the 'maturity' level appropriate for this pack?
7. Are there any important fields missing?
8. Is the rule expression correct and does it match the stated objective?
```
