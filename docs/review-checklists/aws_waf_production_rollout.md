# AWS WAF Production Rollout Checklist

Use this checklist before promoting AWS WAF rules or managed rule groups from Count to enforcement.

## WebACL Readiness

- [ ] Rule order is intentional and documented
- [ ] WebACL scope matches the protected resource type
- [ ] Logging is enabled to CloudWatch Logs, S3, or Kinesis Data Firehose
- [ ] Sampled requests are enabled for every new rule

## IP Sets and Access Controls

- [ ] Administrative IP sets are current
- [ ] Emergency break-glass IP additions are documented
- [ ] Monitoring or health-check sources are excluded only where justified

## API and Auth Flows

- [ ] Recovery endpoints have their own rate-based rule
- [ ] GraphQL introspection behavior is explicitly documented
- [ ] Public API burst thresholds are based on real metrics
- [ ] Internal or callback paths are excluded from generic public thresholds

## Promotion Gate

- [ ] CountedRequests trends are understood
- [ ] Sampled requests were reviewed for each rule that will enforce
- [ ] Rollback path is documented per rule
- [ ] A single owner is responsible for promotion approval
