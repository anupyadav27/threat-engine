# STORY-CWPP-01: CWPP Runtime Tab — CIEM Behavioral Events Integration

## Track
CWPP Investigation Journey — Sprint 1

## Priority
P1 — surfaces the critical CIEM→CWPP runtime connection that currently doesn't exist

## Story
As a security analyst on the CWPP runtime workload tab, I need to see CIEM behavioral events (e.g. kubectl exec abuse, anomalous container API calls) that are detected by the CIEM engine for the same accounts, so I can connect "privileged containers present" (static posture) with "kubectl exec was actually used at 3am" (behavioral detection) in one view.

## Current State

`engines/cwpp/cwpp_engine/workloads/runtime.py` calls only `container-security` engine:
```python
# Current: only calls container-sec
response = await self.http_client.get(
    f"{CONTAINER_SEC_URL}/api/v1/container-security/ui-data",
    ...
)
```

`shared/api_gateway/bff/cwpp.py` (lines ~182-184) passes through `runtime_findings` only — no CIEM events.

The frontend `cwpp/page.jsx` Runtime tab has no CIEM connection card.

## Files to Modify
- `engines/cwpp/cwpp_engine/workloads/runtime.py` — add CIEM engine call
- `engines/cwpp/cwpp_engine/core/http_client.py` — add `CIEM_ENGINE_URL`
- `shared/api_gateway/bff/cwpp.py` — pass through `ciem_runtime_events`
- `frontend/src/app/cwpp/page.jsx` — add `<CiemRuntimeCard>` to Runtime tab
- `frontend/src/components/cwpp/CiemRuntimeCard.jsx` — **NEW**

## Exact Changes

### 1. `http_client.py` — add CIEM URL

Add alongside existing engine URLs:
```python
CIEM_ENGINE_URL = os.getenv("CIEM_ENGINE_URL", "http://engine-ciem/api/v1")
```

### 2. `runtime.py` — parallel CIEM call with graceful degradation

```python
async def get_runtime_data(self, scan_run_id: str, tenant_id: str, account_ids: list[str]) -> dict:
    # Existing container-sec call (unchanged)
    container_task = self.http_client.get(
        f"{CONTAINER_SEC_URL}/api/v1/container-security/ui-data",
        params={"scan_run_id": scan_run_id, "tenant_id": tenant_id}
    )
    
    # New CIEM behavioral events call
    ciem_task = self._fetch_ciem_runtime_events(scan_run_id, tenant_id, account_ids)
    
    # Run in parallel
    container_result, ciem_result = await asyncio.gather(
        container_task, ciem_task, return_exceptions=True
    )
    
    # Graceful degradation: if CIEM fails, return empty
    ciem_runtime_events = ciem_result if not isinstance(ciem_result, Exception) else {
        "count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
        "link_available": False, "sample_findings": []
    }
    
    return {
        **existing_runtime_data,
        "ciem_runtime_events": ciem_runtime_events
    }

async def _fetch_ciem_runtime_events(self, scan_run_id, tenant_id, account_ids):
    try:
        resp = await self.http_client.get(
            f"{CIEM_ENGINE_URL}/ciem/findings",
            params={
                "action_category": "runtime",
                "scan_run_id": scan_run_id,
                "tenant_id": tenant_id,
                "limit": 10  # sample only
            },
            timeout=5.0  # hard 5s timeout — do not block CWPP for CIEM
        )
        findings = resp.get("findings", [])
        total = resp.get("total", 0)
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.get("severity", "low")
            if sev in counts:
                counts[sev] += 1
        return {
            "count": total,
            **counts,
            "link_available": True,
            "sample_findings": [
                {
                    "title": f.get("title", ""),
                    "severity": f.get("severity"),
                    "actor_principal": f.get("actor_principal", ""),
                    "event_time": f.get("event_time", "")
                }
                for f in findings[:3]  # max 3 samples
            ]
        }
    except Exception:
        return {
            "count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
            "link_available": False, "sample_findings": []
        }
```

### 3. `bff/cwpp.py` — pass through `ciem_runtime_events`

In the runtime data section of the BFF response builder, add:
```python
"runtime": {
    ...existing runtime fields...,
    "ciemRuntimeEvents": workload_data.get("runtime", {}).get("ciem_runtime_events", {
        "count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
        "link_available": False, "sample_findings": []
    })
}
```

### 4. `CiemRuntimeCard.jsx` — new component

```jsx
// Props: { ciemRuntimeEvents, accountId }
// Shows count + severity breakdown if events present
// Shows "No CIEM runtime events detected" if count == 0
// Shows "CIEM engine unavailable" if link_available == false and count == 0
// CTA link: "/ciem?filter=action_category:runtime&account={accountId}"
```

Card design: `bg-slate-800 rounded-xl p-4 mb-4 border border-indigo-800`

Link: `"View Full Behavioral Timeline in CIEM →"` — `text-indigo-400 hover:text-indigo-300`

### 5. `cwpp/page.jsx` — add CiemRuntimeCard to Runtime tab

In the Runtime tab section, render `<CiemRuntimeCard>` above the existing privileged containers table:
```jsx
<CiemRuntimeCard
  ciemRuntimeEvents={data.workloadData.runtime.ciemRuntimeEvents}
  accountId={data.accountId}
/>
```

## Acceptance Criteria

- [ ] Runtime tab shows `CiemRuntimeCard` with CIEM event count and severity breakdown when CIEM engine returns runtime findings
- [ ] CWPP dashboard loads within 200ms added latency when CIEM times out (5s hard timeout, `return_exceptions=True`)
- [ ] "View Full Behavioral Timeline in CIEM →" link routes to `/ciem` with `action_category=runtime` filter pre-applied
- [ ] If CIEM engine is unreachable, card shows "CIEM engine unavailable" — CWPP still loads normally
- [ ] CWPP posture score (`cwpp_posture_score`) is NOT changed by CIEM runtime events (score formula unchanged)
- [ ] `ciem_runtime_events` is tenant-scoped (CIEM engine enforces this via AuthContext forwarded from CWPP)

## Security Checklist
- [ ] CIEM engine URL is internal ClusterIP (`http://engine-ciem`) — not user-supplied, no SSRF risk
- [ ] AuthContext header forwarded from CWPP to CIEM call (tenant isolation via X-Auth-Context)
- [ ] 5-second timeout prevents CWPP from blocking on CIEM engine slowness
- [ ] `sample_findings` strips `credential_ref` and `event_raw` — CWPP should pass only title/severity/principal/time
- [ ] `asyncio.gather(..., return_exceptions=True)` ensures CIEM failure does not crash CWPP

## Definition of Done
- [ ] `runtime.py` makes parallel CIEM call with graceful degradation
- [ ] BFF passes `ciemRuntimeEvents` to frontend
- [ ] Runtime tab renders `CiemRuntimeCard`
- [ ] Manual verify: port-forward CWPP, call `/api/v1/cwpp/dashboard`, confirm `ciem_runtime_events` in runtime section
- [ ] Manual verify: deliberately break CIEM URL, confirm CWPP still returns 200