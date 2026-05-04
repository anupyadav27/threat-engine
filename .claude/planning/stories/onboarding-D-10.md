---
story_id: onboarding-D-10
title: Frontend — schedule modal + region/service scope selection
status: ready
sprint: onboarding-revamp-D
depends_on: [onboarding-C-6, onboarding-C-8, onboarding-D-8]
blocks: [onboarding-D-11]
sme: React/Next.js 15 engineer
estimate: 2 days
---

# Story: Frontend — schedule modal + region/service scope selection

## User Story
As a tenant_admin, I want to attach a schedule to a cloud account with optional
region/service scope selection, so that I can configure daily compliance scans on
production regions only without scanning dev regions.

## Context
This is the "ATTACH_SCHEDULE" step in the onboarding wizard (D8) and also a standalone
modal accessible from the account cards page.

The schedule modal allows:
1. Cron preset selection (Daily / Weekly / Monthly / Custom)
2. Region multi-select (populated from discovered regions for this account, or free-text)
3. Service filter (include/exclude checkboxes by service category)
4. Engine selection (which engines to run — defaults from account_type YAML)
5. Summary preview of "next run" time
6. Submit → `POST /gateway/api/v1/schedules/`

Also builds a "Run Now" button that calls `POST /gateway/api/v1/schedules/{id}/run-now`
or `POST /gateway/api/v1/cloud-accounts/{id}/scan` (ad-hoc).

## Files to Create/Modify
- `frontend/src/components/onboarding/ScheduleModal.jsx` — schedule creation modal
- `frontend/src/components/accounts/AccountCard.jsx` — add "Run Now" + "Edit Schedule" buttons
- `frontend/src/lib/schedule-utils.js` — cron preset → expression helpers

## Implementation Notes

### Cron presets

```javascript
// frontend/src/lib/schedule-utils.js
export const CRON_PRESETS = [
  { label: "Daily at midnight UTC",  value: "0 0 * * *" },
  { label: "Daily at 2 AM UTC",      value: "0 2 * * *" },
  { label: "Weekly (Sunday 2 AM)",   value: "0 2 * * 0" },
  { label: "Monthly (1st at 2 AM)",  value: "0 2 1 * *" },
  { label: "Custom",                 value: "custom" },
];

export function getNextRunTime(cronExpression) {
  // Use cron-parser or cronstrue npm package
  // Returns human-readable "next run: Tuesday, 2 AM UTC"
}
```

### `ScheduleModal` component

```jsx
export function ScheduleModal({ account, existingSchedule, onClose, onSaved }) {
  const catalog = getAccountTypeCatalog();
  const defaultEngines = getDefaultEngines(account.account_type, catalog);
  const [form, setForm] = useState({
    cron_expression: existingSchedule?.cron_expression || "0 2 * * 0",
    include_regions: existingSchedule?.include_regions || [],
    exclude_regions: existingSchedule?.exclude_regions || [],
    include_services: existingSchedule?.include_services || [],
    engines_requested: existingSchedule?.engines_requested || defaultEngines,
  });

  async function handleSubmit() {
    const method = existingSchedule ? 'PATCH' : 'POST';
    const url = existingSchedule
      ? `/gateway/api/v1/schedules/${existingSchedule.id}`
      : `/gateway/api/v1/schedules/`;
    await fetch(url, {
      method,
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ ...form, account_id: account.id, tenant_id: account.tenant_id }),
    });
    onSaved();
  }

  return (
    <Modal title={existingSchedule ? "Edit Schedule" : "Create Schedule"}>
      <CronPicker value={form.cron_expression} onChange={v => setForm(f => ({...f, cron_expression: v}))} />
      <RegionSelect
        provider={account.provider}
        selected={form.include_regions}
        excluded={form.exclude_regions}
        onChange={(inc, exc) => setForm(f => ({...f, include_regions: inc, exclude_regions: exc}))}
      />
      <ServiceFilter
        accountType={account.account_type}
        selected={form.include_services}
        onChange={v => setForm(f => ({...f, include_services: v}))}
      />
      <EngineSelector
        available={defaultEngines}
        selected={form.engines_requested}
        onChange={v => setForm(f => ({...f, engines_requested: v}))}
      />
      <p className="text-sm text-gray-600">
        Next run: {getNextRunTime(form.cron_expression)}
      </p>
      <Button onClick={handleSubmit}>Save Schedule</Button>
    </Modal>
  );
}
```

### `AccountCard` additions

```jsx
// In AccountCard:
<Button size="sm" onClick={() => triggerRunNow(account.id)}>Run Now</Button>
<Button size="sm" variant="outline" onClick={() => setShowScheduleModal(true)}>
  {account.schedule ? "Edit Schedule" : "Add Schedule"}
</Button>
```

## Acceptance Criteria
- [ ] AC1: Schedule modal opens from wizard ATTACH_SCHEDULE step and from AccountCard
- [ ] AC2: Cron presets render correctly; "Custom" shows a cron expression input
- [ ] AC3: "Next run" preview updates in real time as cron expression changes
- [ ] AC4: Region multi-select defaults to empty (all regions) and allows selection
- [ ] AC5: Engine selector shows engines appropriate for account_type (from YAML)
- [ ] AC6: `POST /gateway/api/v1/schedules/` called on submit; 201 → modal closes
- [ ] AC7: Existing schedule: modal pre-fills from existing values, uses PATCH on submit
- [ ] AC8: "Run Now" button on AccountCard calls `/schedules/{id}/run-now` → toast notification

## Definition of Done
- [ ] ScheduleModal renders and submits correctly for create + update
- [ ] include_regions, exclude_regions, include_services, engines_requested all pass to API
- [ ] AccountCard has Run Now and Edit/Add Schedule buttons
- [ ] Manual browser test: create schedule with region filter, verify API payload
- [ ] bmad-security-reviewer: no BLOCKERs
