# RULE-S06 — Frontend: Rules Page Suppress Action

**File**: `frontend/src/app/rules/page.jsx`  
**Status**: Ready for dev

## Goal
Add an Actions column to the rules table with a Suppress dropdown (rule/service/technology scope) and a right-side slide-out panel for creating suppressions.

## Acceptance Criteria
- [ ] Actions column at end of rules table
- [ ] Suppressed rules show "Suppressed" badge in Status column
- [ ] "Suppress ▾" dropdown with 3 options: this rule / all for service / all for technology
- [ ] Slide-out panel: scope level (tenant/account), account selector, reason, expiry
- [ ] Submit calls POST /rules/suppress via postToEngine
- [ ] After submit: rule status updates inline + panel closes
- [ ] Suppressed rule shows "Lift" button instead of "Suppress"
