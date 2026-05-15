# RULE-S01 — DB Migration: rule_suppressions Table

**Engine**: check DB (`threat_engine_check`)  
**Status**: Ready for dev

## Goal
Create the `rule_suppressions` table that stores per-tenant and per-account rule suppression records at rule / service / technology scope.

## Acceptance Criteria
- [ ] `rule_suppressions` table exists in `threat_engine_check`
- [ ] Unique index prevents duplicate suppressions (handles NULL account_id and provider)
- [ ] Indexes on `(tenant_id)`, `(tenant_id, account_id)`, `(scope_type, scope_value)`, `(expires_at)`
- [ ] Migration file follows existing migration naming convention

## Migration File
`shared/database/migrations/check_rule_suppressions_001.sql`
