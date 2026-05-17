# RULE-S04 — BFF: Suppressions View + Rules is_suppressed

**Engine**: gateway BFF (`shared/api_gateway/bff/`)  
**Status**: Ready for dev

## Goal
Replace the dead policies BFF with a real suppressions view. Also enrich the rules BFF response with `is_suppressed` per rule.

## Changes
- `policies.py` → repurposed to serve `GET /api/v1/views/suppressions`
- `rules.py` → add `is_suppressed` + `suppression_details` fields per rule

## Acceptance Criteria
- [ ] `GET /api/v1/views/suppressions` returns list of active suppressions for tenant
- [ ] Response includes KPIs: tenant_wide_count, account_level_count, expiring_soon_count
- [ ] Rules BFF includes `is_suppressed: bool` and `suppression_scope` per rule
