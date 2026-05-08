---
story_id: onboarding-D-11
title: Frontend — run-now + bulk scan-all + scan progress page
status: ready
sprint: onboarding-revamp-D
depends_on: [onboarding-C-7, onboarding-C-9, onboarding-D-10]
blocks: []
sme: React/Next.js 15 engineer
estimate: 1 day
---

# Story: Frontend — run-now + bulk scan-all + scan progress page

## User Story
As a tenant_admin, I want to trigger an immediate scan and watch its progress in real time,
and I want a "Scan All Now" button to kick off all my accounts at once.

## Context
Story C7 adds ad-hoc scan. Story C9 adds bulk run-all. This story builds the frontend:
1. AccountsPage: "Scan All Now" button at the top → calls `POST /gateway/api/v1/schedules/run-all`
2. AccountCard: "Run Now" button (already started in D10) → calls adhoc scan endpoint
3. ScanProgressPage: `/scans/{scan_run_id}` — shows real-time scan pipeline progress
4. AccountsPage: last scan status badge (from `scan_orchestration.status`)

The scan progress page uses the pipeline-monitor engine (SSE streaming) to show
live per-engine status updates.

## Files to Create/Modify
- `frontend/src/app/accounts/page.jsx` — add "Scan All Now" button + last-scan status
- `frontend/src/app/scans/[scanRunId]/page.jsx` — new scan progress page
- `frontend/src/components/scans/ScanPipelineProgress.jsx` — pipeline stages display

## Implementation Notes

### "Scan All Now" button

```jsx
// In AccountsPage:
async function handleScanAllNow() {
  setScanning(true);
  const resp = await fetch('/gateway/api/v1/schedules/run-all', { method: 'POST' });
  const data = await resp.json();
  toast.success(`Submitted ${data.submitted} scans`);
  if (data.warning) toast.warning(data.warning);
  setScanning(false);
  router.refresh(); // re-fetch scan status badges
}

<Button onClick={handleScanAllNow} loading={scanning}>
  Scan All Now
</Button>
```

### `ScanProgressPage`

```jsx
// frontend/src/app/scans/[scanRunId]/page.jsx
export default function ScanProgressPage({ params: { scanRunId } }) {
  const [progress, setProgress] = useState(null);

  useEffect(() => {
    // Use pipeline-monitor SSE endpoint
    const es = new EventSource(`/gateway/api/v1/pipeline-monitor/scans/${scanRunId}/stream`);
    es.onmessage = (e) => setProgress(JSON.parse(e.data));
    es.onerror = () => es.close();
    return () => es.close();
  }, [scanRunId]);

  return (
    <div>
      <h1>Scan Progress</h1>
      <ScanPipelineProgress scan_run_id={scanRunId} progress={progress} />
    </div>
  );
}
```

### `ScanPipelineProgress` component

Shows the 8 pipeline stages in order with status badges:
```
Discovery → Inventory → Check → Threat → Compliance/IAM/DataSec/Network → Risk → Done
```

```jsx
const PIPELINE_STAGES = [
  { key: 'discovery',   label: 'Discovery' },
  { key: 'inventory',   label: 'Inventory' },
  { key: 'check',       label: 'Check' },
  { key: 'threat',      label: 'Threat' },
  { key: 'compliance',  label: 'Compliance' },
  { key: 'iam',         label: 'IAM' },
  { key: 'network',     label: 'Network' },
  { key: 'datasec',     label: 'DataSec' },
  { key: 'risk',        label: 'Risk' },
];

export function ScanPipelineProgress({ progress }) {
  return (
    <div className="flex items-center gap-2">
      {PIPELINE_STAGES.map(stage => (
        <StageBadge
          key={stage.key}
          label={stage.label}
          status={progress?.engines_completed?.includes(stage.key) ? 'complete'
                : progress?.current_engine === stage.key ? 'running' : 'pending'}
        />
      ))}
    </div>
  );
}
```

## Acceptance Criteria
- [ ] AC1: "Scan All Now" button on AccountsPage calls `POST /schedules/run-all` and shows toast with count
- [ ] AC2: "Run Now" on AccountCard calls ad-hoc scan endpoint → redirects to ScanProgressPage
- [ ] AC3: ScanProgressPage subscribes to SSE stream from pipeline-monitor engine
- [ ] AC4: Pipeline stages update in real time as scan progresses
- [ ] AC5: Final state: all stages green + "Scan Complete" message + "View Results" button
- [ ] AC6: AccountCard shows last scan status badge (completed/failed/running)
- [ ] AC7: Bulk run-all warning message shown if >10 accounts were capped

## Definition of Done
- [ ] "Scan All Now" button + toast notification
- [ ] `/scans/{scan_run_id}` route renders ScanProgressPage
- [ ] SSE stream connected to pipeline-monitor engine
- [ ] Pipeline stage badges update live
- [ ] Manual browser test: trigger scan, watch progress page update
- [ ] bmad-security-reviewer: no BLOCKERs
