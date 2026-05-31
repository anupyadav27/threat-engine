# /cspm-scan-health

Diagnose stuck, failed, or incomplete CSPM pipeline scan runs. Checks each engine in pipeline order and surfaces the exact failure point.

## Usage
```
/cspm-scan-health
/cspm-scan-health <scan_run_id>
/cspm-scan-health --tenant <tenant_id>
```

Examples:
```
/cspm-scan-health
/cspm-scan-health 4f2a1b3c-8e7d-4f9a-b2c1-3d4e5f6a7b8c
/cspm-scan-health --tenant 12
```

## Step 1 — Get latest scan_run_id (if not provided)

Port-forward onboarding engine and query:
```bash
kubectl port-forward svc/engine-onboarding 9901:80 -n threat-engine-engines &
python3 -c "
import urllib.request, json
r = urllib.request.urlopen('http://localhost:9901/api/v1/internal/latest-scan', timeout=5)
print(json.loads(r.read()))
"
kill %1
```

Or via DB (copy SQL to pod):
```sql
SELECT scan_run_id, tenant_id, overall_status, provider, started_at, completed_at,
       engines_completed
FROM scan_orchestration
ORDER BY started_at DESC LIMIT 5;
```

## Step 2 — Overall pipeline status

```sql
SELECT scan_run_id, overall_status, provider, tenant_id,
       started_at, completed_at,
       EXTRACT(EPOCH FROM (COALESCE(completed_at, NOW()) - started_at)) / 60 AS runtime_minutes,
       engines_completed
FROM scan_orchestration
WHERE scan_run_id = '<uuid>';
```

Status meanings:
- `running` + no `completed_at` + runtime > 30min → stuck
- `failed` → check `engines_completed` to find which engine blocked
- `completed` + short runtime → may have skipped engines (check counts)

## Step 3 — Per-engine finding counts

```sql
SELECT
  (SELECT COUNT(*) FROM discovery_findings WHERE scan_run_id='<uuid>') AS disc,
  (SELECT COUNT(*) FROM check_findings WHERE scan_run_id='<uuid>') AS check,
  (SELECT COUNT(*) FROM threat_findings WHERE scan_run_id='<uuid>') AS threat,
  (SELECT COUNT(*) FROM compliance_findings WHERE scan_run_id='<uuid>') AS compliance,
  (SELECT COUNT(*) FROM iam_findings WHERE scan_run_id='<uuid>') AS iam,
  (SELECT COUNT(*) FROM network_findings WHERE scan_run_id='<uuid>') AS network,
  (SELECT COUNT(*) FROM datasec_findings WHERE scan_run_id='<uuid>') AS datasec,
  (SELECT COUNT(*) FROM cdr_findings WHERE scan_run_id='<uuid>') AS cdr,
  (SELECT COUNT(*) FROM risk_scores WHERE scan_run_id='<uuid>') AS risk,
  (SELECT COUNT(*) FROM attack_paths WHERE scan_run_id='<uuid>') AS attack_paths;
```

Expected non-zero: `disc` → `check` → `threat` → `compliance` → `iam` → `network` → `risk`
Zero count at any stage = that engine did not write findings for this scan.

## Step 4 — Engine pod health check

For any engine that shows 0 findings:
```bash
kubectl logs -l app=<engine> -n threat-engine-engines --tail=100 --since=1h \
  | grep -E 'ERROR|FATAL|Traceback|scan_run_id|completed|starting'
```

Common failure signatures:
- `Connection refused` → DB not reachable from pod
- `401 Unauthorized` → auth context not passed correctly from Argo step
- `scan_run_id not found` → orchestration row missing or wrong DB targeted
- `ImportError` → bad Docker image (missing dependency)
- No logs at all → pod may be in CrashLoopBackOff

```bash
kubectl get pods -l app=<engine> -n threat-engine-engines
kubectl describe pod -l app=<engine> -n threat-engine-engines | grep -A 10 Events
```

## Step 5 — Argo workflow status

```bash
kubectl get workflows -n argo | head -10
kubectl get workflow <workflow-name> -n argo -o jsonpath='{.status.phase}'
kubectl get workflow <workflow-name> -n argo -o jsonpath='{.status.nodes}' | python3 -m json.tool | grep -E 'displayName|phase|message' | head -60
```

Failed Argo node = that engine step failed. Check the node's message for the error.

## Step 6 — Diagnosis summary

Output a table:
```
Engine        | Findings | Pod Status | Argo Phase | Diagnosis
------------- | -------- | ---------- | ---------- | ---------
discoveries   | 1842     | Running    | Succeeded  | OK
check         | 9341     | Running    | Succeeded  | OK
threat        | 0        | Running    | Failed     | AUTH_ERROR — X-Auth-Context missing in Argo step
compliance    | 0        | Running    | Skipped    | Blocked by threat failure
```

## Common fixes by diagnosis

| Diagnosis | Fix |
|-----------|-----|
| AUTH_ERROR in Argo step | Check `cspm-pipeline.yaml` — Argo steps must pass `X-Auth-Context`, not `X-Internal-Secret` for standard endpoints |
| 0 discoveries | Check cloud credentials in Secrets Manager; check engine-discoveries pod logs |
| 0 check findings | Verify `rule_metadata.active=true` for the CSP; check scan_run_id in scan_orchestration |
| DB connection refused | Check `threat-engine-db-config` ConfigMap values match RDS endpoint |
| CrashLoopBackOff | Bad image — check Dockerfile; run `/cspm-rollback <engine>` |
| Argo workflow not starting | Check Argo controller in `argo` namespace; check ServiceAccount permissions |