---
id: onboarding-D10
title: "Frontend: schedule modal + region/service scope selection"
sprint: D
points: 2
depends_on: [onboarding-C6, onboarding-C8, onboarding-D8]
blocks: [onboarding-D11]
security_blocks: []
nist_csf: PR.DS
owasp_samm: Implementation
csa_ccm: IAM-14
---

## Context

After a cloud account is validated in the wizard (D8), the user is prompted to configure a scan schedule. The default daily schedule (2 AM UTC) is pre-selected, but the user can optionally add region or service exclusions. The schedule modal also surfaces from the Accounts list page — users can edit their schedule settings after initial setup. The schedule CRUD backend is live from C6/C8, and the BFF view is live from D5. This story builds the `ScheduleModal` React component that: (1) shows current schedule settings, (2) allows toggling include/exclude regions via a multi-select, (3) saves via `PATCH /gateway/api/v1/schedules/{id}`. The region list for AWS is sourced from a static catalog constant — no backend call needed for the region list.

## Acceptance Criteria

- [ ] AC1: `ScheduleModal` component opens as a drawer or modal dialog when "Edit Schedule" is clicked on an account card.
- [ ] AC2: Modal shows current `cron_expression` as a human-readable string (e.g., "Daily at 2:00 AM UTC").
- [ ] AC3: "Exclude Regions" multi-select renders the full AWS region list (from `frontend/src/config/aws-regions.ts` constant). For non-AWS providers, region options come from their provider-specific constant.
- [ ] AC4: Selected excluded regions render as removable chips/badges below the multi-select.
- [ ] AC5: "Exclude Services" multi-select renders a list of service names (from `frontend/src/config/aws-services.ts`). At least: `s3`, `ec2`, `rds`, `iam`, `lambda`, `cloudtrail`.
- [ ] AC6: On "Save", calls `PATCH /gateway/api/v1/schedules/{id}` with `{exclude_regions: [], exclude_services: []}` body.
- [ ] AC7: `PATCH` call goes through the gateway (not directly to the onboarding engine).
- [ ] AC8: On successful save, the modal closes and the account card updates to show "X regions excluded" badge.
- [ ] AC9: Schedule modal also appears as step 4 in the onboarding wizard (after validation pass in D8) — pre-populated with the default daily schedule.
- [ ] AC10: "Disable Schedule" checkbox puts the account in adhoc-only mode (calls `PATCH /schedules/{id}` with `{"active": false}`).
- [ ] AC11: Loading state while saving — Save button shows spinner, is disabled during the request.

## Key Files

- `frontend/src/components/onboarding/ScheduleModal.tsx` — Create
- `frontend/src/config/aws-regions.ts` — Create: list of AWS regions with display names
- `frontend/src/config/aws-services.ts` — Create: list of AWS service names
- `frontend/src/app/(portal)/onboarding/[step]/page.tsx` — Wire schedule modal as wizard step 4
- `frontend/src/app/(portal)/accounts/` — Integrate "Edit Schedule" button on account cards

## Technical Notes

**AWS regions constant (subset):**
```ts
// config/aws-regions.ts
export const AWS_REGIONS = [
  { value: 'us-east-1', label: 'US East (N. Virginia)' },
  { value: 'us-east-2', label: 'US East (Ohio)' },
  { value: 'us-west-1', label: 'US West (N. California)' },
  { value: 'us-west-2', label: 'US West (Oregon)' },
  { value: 'ap-south-1', label: 'Asia Pacific (Mumbai)' },
  { value: 'ap-southeast-1', label: 'Asia Pacific (Singapore)' },
  { value: 'ap-southeast-2', label: 'Asia Pacific (Sydney)' },
  { value: 'eu-west-1', label: 'Europe (Ireland)' },
  { value: 'eu-central-1', label: 'Europe (Frankfurt)' },
  // ... add all standard regions
];
```

**Schedule PATCH via gateway:**
```tsx
const saveSchedule = async () => {
  setLoading(true);
  try {
    await fetch(`/gateway/api/v1/schedules/${scheduleId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        exclude_regions: selectedExcludeRegions,
        exclude_services: selectedExcludeServices,
        active: scheduleActive,
      }),
    });
    onClose();
    onSaved();
  } finally {
    setLoading(false);
  }
};
```

**Multi-select component:** Use `shadcn/ui` `Command` + `Popover` pattern (standard in this codebase) or a `Select` with `multiple`. Check existing multi-selects:
```bash
grep -rn "multi.*select\|Select.*multiple\|Command.*Popover" \
  /Users/apple/Desktop/threat-engine/frontend/src/ --include="*.tsx" | head -5
```

**Cron to human-readable:**
```ts
const CRON_LABELS: Record<string, string> = {
  '0 2 * * *': 'Daily at 2:00 AM UTC',
  '0 * * * *': 'Hourly',
  '0 2 * * 1': 'Weekly (Monday 2:00 AM UTC)',
};
const formatCron = (expr: string) => CRON_LABELS[expr] ?? expr;
```

**BFF PATCH passthrough:** The gateway needs to forward `PATCH /gateway/api/v1/schedules/{id}` to the onboarding engine. Check if this route already exists in the gateway routing table:
```bash
grep -rn "schedules\|PATCH.*schedule" \
  /Users/apple/Desktop/threat-engine/shared/api_gateway/ --include="*.py" | head -10
```
If not, add a passthrough route in the gateway.

**Wizard step 4 integration:**
After step 3 (validation pass), wizard advances to step 4. Step 4 renders `<ScheduleModal inlineMode={true} accountId={accountId} />` — inline mode means no dialog wrapper, just the form content.

## Security Checklist

- [ ] `PATCH` goes through the gateway (not direct to engine) — no engine URL in frontend code
- [ ] No tenant_id in the PATCH request body — gateway infers from auth cookie
- [ ] Region and service lists are static catalogs — no user input reflected without validation
- [ ] bmad-security-reviewer gate passed before merge

## Definition of Done

- [ ] All ACs pass
- [ ] Multi-select works for both regions and services
- [ ] "Disable Schedule" sets `active: false` in PATCH
- [ ] Loading spinner on Save button
- [ ] BFF/gateway route for schedule PATCH confirmed
- [ ] Frontend build succeeds
- [ ] bmad-security-reviewer: no BLOCKERs
- [ ] Visual QA: modal renders, saves, closes correctly
