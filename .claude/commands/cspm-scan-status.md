# /cspm-scan-status

Check the status of a CSPM pipeline scan run across all engines.

## Usage
```
/cspm-scan-status <scan_run_id>
```

Or for latest scan:
```
/cspm-scan-status latest
```

## What it checks

For each engine in pipeline order:
1. **scan_orchestration** (onboarding DB) — overall status, engines_completed JSONB
2. **discovery_report** — discovery phase
3. **inventory_report** — inventory phase
4. **check_report** — check phase
5. **threat_report** — threat phase
6. **compliance_report** — compliance phase (parallel)
7. **iam_report** — IAM phase (parallel)
8. **network_report** — network phase (parallel)
9. **datasec_report** — datasec phase (parallel)
10. **risk_report** — risk phase

## Quick SQL reference

```sql
-- Overall status
SELECT scan_run_id, overall_status, engines_completed, started_at, completed_at
FROM scan_orchestration WHERE scan_run_id = '<uuid>';

-- Finding counts per engine
SELECT 
  (SELECT COUNT(*) FROM discovery_findings WHERE scan_run_id='<uuid>') AS discoveries,
  (SELECT COUNT(*) FROM check_findings WHERE scan_run_id='<uuid>') AS checks,
  (SELECT COUNT(*) FROM threat_findings WHERE scan_run_id='<uuid>') AS threats,
  (SELECT COUNT(*) FROM compliance_findings WHERE scan_run_id='<uuid>') AS compliance;
```

## Common issues
- `engines_completed` is JSONB (not TEXT[]) — query with `->` operator
- `overall_status='running'` but engine not progressing → check engine pod logs
- Zero findings for an engine → see that engine's debug workflow in its agent