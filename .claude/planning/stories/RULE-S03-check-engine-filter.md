# RULE-S03 — Check Engine: Suppression-Aware Rule Reader

**Engine**: check engine (`engines/check/common/database/rule_reader.py`)  
**Status**: Ready for dev

## Goal
Add `read_checks_for_service_tenant()` method that accepts tenant_id + account_id and excludes suppressed rules/services/technologies from the returned check list.

## Acceptance Criteria
- [ ] Existing `read_checks_for_service()` unchanged (backward compat)
- [ ] New method `read_checks_for_service_tenant(service, provider, tenant_id, account_id)` added
- [ ] SQL uses NOT EXISTS subquery against rule_suppressions
- [ ] Both tenant-wide (account_id IS NULL) and account-level suppressions are applied
- [ ] Expired suppressions (expires_at < now()) are ignored
