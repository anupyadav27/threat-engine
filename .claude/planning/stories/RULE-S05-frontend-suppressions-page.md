# RULE-S05 — Frontend: /suppressions Page

**File**: `frontend/src/app/suppressions/page.jsx` (new, replaces /policies concept)  
**Status**: Ready for dev

## Goal
Build the suppression management page. Shows all active suppressions for the tenant with KPIs, filterable table, and Lift action per row.

## Acceptance Criteria
- [ ] KPI cards: Tenant-wide, Account-level, Expiring in 30d, By Service
- [ ] Table columns: Scope, Level, Account, Provider, Reason, Expires, Actions
- [ ] Filter by: scope_level, scope_type, provider
- [ ] Lift button calls DELETE /rules/suppressions/{id} via deleteFromEngine
- [ ] Table refreshes after lift
- [ ] Empty state message when no suppressions
