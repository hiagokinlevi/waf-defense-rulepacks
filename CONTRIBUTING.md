# Contributing to waf-defense-rulepacks

Thank you for your interest in contributing. This project grows by practitioners sharing well-documented, tested WAF rule packs. Quality and clarity are more important than quantity.

## Ways to Contribute

- **Add a new pack**: A new WAF rule targeting a specific attack class or vendor
- **Improve an existing pack**: Add tuning notes, fix an expression, update maturity
- **Add a new vendor**: Create the folder structure and first pack for an unsupported vendor
- **Improve documentation**: Deployment guides, tutorials, checklists
- **Improve the validator**: Extend `shared/validators/validate_pack.py`
- **Report issues**: Incorrect rules, false positive patterns, schema gaps

## Before You Start

1. Check existing issues and pull requests to avoid duplicates.
2. For significant additions (new vendor, new schema fields), open an issue first to discuss the approach.
3. All packs must be for **defensive use only**.

## Pack Quality Bar

Every submitted pack must include all required metadata fields (see `shared/schemas/pack_metadata.json`):

- `name`, `vendor`, `category`, `objective`, `risk_mitigated` — clearly written in English
- `severity` — accurately reflects the risk being mitigated
- `potential_side_effects` — honest about known false positive scenarios
- `tuning_notes` — at least one concrete tuning suggestion
- `deployment_notes` — must recommend starting in log/count mode
- `maturity` — set to `draft` for new submissions; will be upgraded after review

## Development Setup

```bash
# Install validator dependencies
pip install jsonschema

# Validate all packs
python shared/validators/validate_pack.py --all

# Validate a single pack
python shared/validators/validate_pack.py --pack cloudflare/waf-rules/block_sqli.json
```

## Pull Request Process

1. Fork the repository and create a feature branch: `feat/add-cloudflare-lfi-pack`
2. Add your pack and run the validator to confirm it passes.
3. Add or update tests in `tests/test_validator.py` if you changed the validator.
4. Open a PR with a clear description:
   - What attack class or risk does this pack address?
   - Which vendor and which rule engine?
   - How was it tested?
   - Known false positive scenarios?
5. A maintainer will review within 7 days.

## Commit Style

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add cloudflare LFI detection pack
fix: correct SQLi expression false positive on search endpoints
docs: add Azure WAF deployment guide
chore: update pack schema to v1.1
```

## Code of Conduct

All contributors are expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
