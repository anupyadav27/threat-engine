---
id: onboarding-D11
title: "Frontend: run-now + bulk scan-all + scan progress page"
sprint: D
points: 1
depends_on: [onboarding-C7, onboarding-C9, onboarding-D10]
blocks: []
security_blocks: []
nist_csf: DE.AE
owasp_samm: Verification
csa_ccm: IAM-14
---

## Context

The backend for ad-hoc scan triggering (C7) and bulk scan-all (C9) is live. This story builds the frontend surface for these capabilities: (1) a "Run Now" button on each account card that calls C7's run-now endpoint, (2) a "Scan All Accounts" button on the tenant overview page that calls C9's run-all endpoint (visible to org_admin only), (3) a scan progress page showing real-time pipeline engine status for an in-flight scan. The scan progress page reads from the BFF `view_scan_history` and `view_scan_detail` views (D6). The scan orchestration progress uses the existing `engines_completed` JSONB field from `scan_orchestration`.

## Acceptance Criteria

- [ ] AC1: Each account card on the Accounts list page has a "Run Now" button (icon button with tooltip).
- [ ] AC2: "Run Now" button is hidden for `viewer` and `analyst` roles (only `tenant_admin`, `org_admin`, `platform_admin` can trigger scans).
- [ ] AC3: Clicking "Run Now" calls `POST /gateway/api/v1/scans/run-now` with `{"account_id": "<id>"}` and shows a toast notification "Scan queued — scan_run_id: {id}".
- [ ] AC4: "Scan All Accounts" button appears on the tenant overview page, visible to `org_admin` and `platform_admin` only.
- [ ] AC5: Clicking "Scan All" calls `POST /gateway/api/v1/scans/run-all` with `{"tenant_id": "<current_tenant_id>"}` and shows a summary toast: "Triggered: N accounts, Skipped: M accounts".
- [ ] AC6: A scan progress page exists at `(portal)/scans/[scan_run_id]/` that shows per-engine pipeline status.
- [ ] AC7: Scan progress page renders a pipeline diagram with engine stages: `Discovery → Inventory → Check → Threat → [Compliance | IAM | DataSec | Network]`. Each stage shows a status icon: Pending (grey) | Running (spinner) | Completed (green) | Failed (red).
- [ ] AC8: Scan progress page polls `GET /gateway/api/v1/views/scan_detail?scan_run_id={id}` every 10 seconds until all engines in `engines_requested` appear in `engines_completed`.
- [ ] AC9: Scan history table on the Accounts detail page lists past scans with `scan_run_id`, timestamp, status, and a "View Progress" link to the scan progress page.
- [ ] AC10: "Re-run" button on completed/failed scans in the history table calls `POST /gateway/api/v1/views/scan_rerun` with `{"scan_run_id": "<id>"}`.

## Key Files

- `frontend/src/components/accounts/RunNowButton.tsx` — Create
- `frontend/src/components/accounts/ScanAllButton.tsx` — Create
- `frontend/src/app/(portal)/scans/[scan_run_id]/page.tsx` — Create scan progress page
- `frontend/src/components/scans/PipelineDiagram.tsx` — Create pipeline visualization
- `frontend/src/app/(portal)/accounts/[account_id]/page.tsx` — Add scan history table

## Technical Notes

**RunNowButton component:**
```tsx
// components/accounts/RunNowButton.tsx
'use client';

export function RunNowButton({ accountId }: { accountId: string }) {
  const { role } = useAuthContext();
  if (!['tenant_admin', 'org_admin', 'platform_admin'].includes(role)) return null;

  const handleRunNow = async () => {
    const resp = await fetch('/gateway/api/v1/scans/run-now', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ account_id: accountId }),
    });
    const { scan_run_id } = await resp.json();
    toast.success(`Scan queued — ID: ${scan_run_id}`);
  };

  return <Button size="sm" onClick={handleRunNow} title="Run scan now">▶</Button>;
}
```

**ScanAllButton component:**
```tsx
export function ScanAllButton({ tenantId }: { tenantId: string }) {
  const { role } = useAuthContext();
  if (!['org_admin', 'platform_admin'].includes(role)) return null;

  const handleScanAll = async () => {
    const resp = await fetch('/gateway/api/v1/scans/run-all', {
      method: 'POST',
      body: JSON.stringify({ tenant_id: tenantId }),
    });
    const { triggered, skipped } = await resp.json();
    toast.success(`Triggered: ${triggered.length}, Skipped: ${skipped.length}`);
  };

  return <Button onClick={handleScanAll}>Scan All Accounts</Button>;
}
```

**Pipeline diagram stages:**
```ts
const PIPELINE_STAGES = [
  { id: 'discovery', label: 'Discovery' },
  { id: 'inventory', label: 'Inventory' },
  { id: 'check', label: 'Check' },
  { id: 'threat', label: 'Threat' },
  { id: 'compliance', label: 'Compliance' },
  { id: 'iam', label: 'IAM' },
  { id: 'datasec', label: 'Data Security' },
  { id: 'network-security', label: 'Network' },
];
```

**PipelineDiagram status determination:**
```tsx
function getStageStatus(stage: string, enginesRequested: string[], enginesCompleted: string[]) {
  if (!enginesRequested.includes(stage)) return 'skipped';
  if (enginesCompleted.includes(stage)) return 'completed';
  return 'running';  // in engines_requested but not completed = still running
}
```

**Polling for scan progress page:**
```tsx
useEffect(() => {
  const poll = setInterval(async () => {
    const data = await fetchView(`scan_detail?scan_run_id=${scanRunId}`);
    setScanDetail(data);
    const allDone = data.engines_requested.every(
      (e: string) => data.engines_completed.includes(e) || data.status === 'failed'
    );
    if (allDone) clearInterval(poll);
  }, 10000);
  return () => clearInterval(poll);
}, [scanRunId]);
```

**Check existing scan status patterns:**
```bash
ls /Users/apple/Desktop/threat-engine/frontend/src/app/\(portal\)/scans/ 2>/dev/null
grep -rn "scan_run_id\|pipeline.*status\|engines_completed" \
  /Users/apple/Desktop/threat-engine/frontend/src/ --include="*.tsx" | head -10
```

## Security Checklist

- [ ] "Run Now" and "Scan All" hidden for `viewer` and `analyst` roles
- [ ] `tenant_id` in Scan All comes from auth context — not a user-editable field
- [ ] No engine URLs in frontend — all calls go through `/gateway/`
- [ ] bmad-security-reviewer gate passed before merge

## Definition of Done

- [ ] All ACs pass
- [ ] "Run Now" calls C7 endpoint correctly; toast shows scan_run_id
- [ ] "Scan All" calls C9 endpoint; toast shows triggered/skipped counts
- [ ] Scan progress page polls and updates pipeline stages
- [ ] Re-run button triggers new scan
- [ ] `viewer` and `analyst` cannot see Run Now or Scan All buttons
- [ ] Frontend build succeeds
- [ ] bmad-security-reviewer: no BLOCKERs
