# Threat Engine — Operations Runbook

## Service Inventory

| Service | Port | Namespace | Layer | DB |
|---------|------|-----------|-------|----|
| engine-discoveries | 8001 | threat-engine-engines | 0 (onboarding) | threat_engine_discoveries |
| engine-inventory | 8022 | threat-engine-engines | 1 | threat_engine_inventory |
| engine-container | 8006 | threat-engine-engines | 1 | threat_engine_container |
| engine-api | 8021 | threat-engine-engines | 1 | threat_engine_api |
| engine-check | 8002 | threat-engine-engines | 2 | threat_engine_check |
| engine-iam | 8001 | threat-engine-engines | 2 | threat_engine_iam |
| engine-secops | 8005 | threat-engine-engines | 2 | threat_engine_secops |
| engine-network | 8007 | threat-engine-engines | 2 | threat_engine_network |
| engine-ai-security | 8032 | threat-engine-engines | 2 | threat_engine_ai_security |
| engine-threat | 8020 | threat-engine-engines | 3 | threat_engine_threat |
| engine-datasec | 8003 | threat-engine-engines | 3 | threat_engine_datasec |
| engine-supplychain | 8008 | threat-engine-engines | 3 | threat_engine_supplychain |
| engine-datasec-enhanced | 8033 | threat-engine-engines | 3 | threat_engine_datasec_enhanced |
| engine-compliance | 8000 | threat-engine-engines | 4 | threat_engine_compliance |
| engine-risk | 8009 | threat-engine-engines | 4 | threat_engine_risk |
| log-collector | 8030 | threat-engine-engines | 0.5 | threat_engine_logs |
| external-collector | 8031 | threat-engine-engines | 0.5 | threat_engine_external |
| pipeline-worker | — | threat-engine-engines | orchestrator | — |

## Daily Operations

### Health Check Procedure

```bash
# 1. Verify all pods are running
kubectl get pods -n threat-engine-engines -o wide

# 2. Check for CrashLoopBackOff or pending pods
kubectl get pods -n threat-engine-engines --field-selector=status.phase!=Running

# 3. Hit health endpoints (via port-forward or ingress)
for svc in engine-discoveries engine-check engine-threat engine-compliance; do
  kubectl exec -n threat-engine-engines deploy/$svc -- \
    curl -sf http://localhost:8080/api/v1/health/ready || echo "$svc NOT READY"
done

# 4. Check DLQ depth
aws sqs get-queue-attributes \
  --queue-url $SQS_DLQ_URL \
  --attribute-names ApproximateNumberOfMessages

# 5. Check cache freshness (external-collector)
kubectl port-forward svc/external-collector 8031:8031 -n threat-engine-engines &
curl -s http://localhost:8031/api/v1/health/cache-status | jq .
```

### Monitor Scan Progress

```bash
# Query scan_orchestration for recent scans
kubectl port-forward svc/postgres 5432:5432 -n threat-engine-engines &
psql -h localhost -U postgres -d threat_engine_onboarding -c "
  SELECT orchestration_id, tenant_id, status,
         discovery_scan_id IS NOT NULL AS discovery_done,
         check_scan_id IS NOT NULL AS check_done,
         container_scan_id IS NOT NULL AS container_done,
         risk_scan_id IS NOT NULL AS risk_done,
         created_at, updated_at
  FROM scan_orchestration
  ORDER BY created_at DESC LIMIT 10;
"
```

## Troubleshooting

### Scan Stuck or Slow

1. **Check pipeline worker logs:**
   ```bash
   kubectl logs -f deploy/pipeline-worker -n threat-engine-engines --tail=100
   ```

2. **Identify which layer is stuck:**
   Look for "Layer-X-* starting" without a corresponding "complete" log.

3. **Check the specific engine:**
   ```bash
   kubectl logs -f deploy/engine-<name> -n threat-engine-engines --tail=200
   ```

4. **Check for DB connection issues:**
   ```bash
   kubectl logs deploy/engine-<name> -n threat-engine-engines | grep -i "connection\|timeout\|error"
   ```

5. **Check resource limits:**
   ```bash
   kubectl top pods -n threat-engine-engines --sort-by=memory
   ```

### Cache Stale

1. **Check cache status:**
   ```bash
   curl http://localhost:8031/api/v1/health/cache-status
   ```

2. **Trigger manual refresh:**
   ```bash
   curl -X POST http://localhost:8031/api/v1/refresh \
     -H "Content-Type: application/json" \
     -d '{"sources": ["nvd", "threat_intel"]}'
   ```

3. **Check collector logs:**
   ```bash
   kubectl logs deploy/external-collector -n threat-engine-engines --tail=100
   ```

4. **Verify API credentials** in Secrets Manager.

### Service Not Responding

1. **Check pod status:**
   ```bash
   kubectl describe pod -l app=engine-<name> -n threat-engine-engines
   ```

2. **Check previous container logs (if restarting):**
   ```bash
   kubectl logs deploy/engine-<name> -n threat-engine-engines --previous
   ```

3. **Check resource limits and OOM kills:**
   ```bash
   kubectl get events -n threat-engine-engines --field-selector reason=OOMKilled
   ```

4. **Restart if needed:**
   ```bash
   kubectl rollout restart deploy/engine-<name> -n threat-engine-engines
   kubectl rollout status deploy/engine-<name> -n threat-engine-engines
   ```

### High Error Rate (> 5%)

1. **Check Prometheus alert details.**

2. **Review error logs:**
   ```bash
   kubectl logs deploy/engine-<name> -n threat-engine-engines | grep -i "error\|exception" | tail -50
   ```

3. **Check external API rate limits** (GitHub, NVD, Docker Hub).

4. **Check DB connection pool exhaustion:**
   Look for "pool timeout" or "too many connections" in logs.

## Incident Response

### Critical: Service Down

1. Page on-call via PagerDuty alert.
2. Check pod status: `kubectl get pods -n threat-engine-engines`
3. Check RDS health in AWS Console.
4. Check node status: `kubectl get nodes`
5. If pod is crash-looping, check logs: `kubectl logs --previous`
6. Rollback if recent deployment: `kubectl rollout undo deploy/engine-<name>`
7. Monitor recovery via Grafana dashboard.

### Warning: Error Rate > 5%

1. Check which engine(s) affected in Prometheus.
2. Review error logs for root cause.
3. If external API: check rate limits, increase backoff.
4. If DB: check connection count, pool status, RDS metrics.
5. If transient: monitor for self-recovery.

### Warning: Cache Stale

1. Trigger manual refresh via API.
2. Check collector logs for collection errors.
3. Verify API credentials haven't expired.
4. If persistent: create schedule for more frequent refreshes.

## Scaling

### Increase Scan Throughput

```bash
# Scale pipeline worker
kubectl scale deploy/pipeline-worker --replicas=3 -n threat-engine-engines

# Scale individual engines
kubectl scale deploy/engine-check --replicas=2 -n threat-engine-engines
```

### Reduce Scan Duration

1. Add database indexes for frequently queried columns.
2. Profile slow queries: check `engine_database_query_duration_seconds` metric.
3. Optimize rule conditions (reduce composite rule depth).
4. Increase engine resource limits if CPU/memory bound.

## Backup and Disaster Recovery

### RDS Backup

```bash
# Create manual snapshot
aws rds create-db-snapshot \
  --db-instance-identifier threat-engine-rds \
  --db-snapshot-identifier threat-engine-$(date +%Y%m%d)

# List snapshots
aws rds describe-db-snapshots \
  --db-instance-identifier threat-engine-rds \
  --query 'DBSnapshots[*].[DBSnapshotIdentifier,SnapshotCreateTime,Status]'
```

### Restore from Snapshot

```bash
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier threat-engine-rds-restored \
  --db-snapshot-identifier threat-engine-20260303
```

## Observability Links

| Tool | URL | Purpose |
|------|-----|---------|
| Grafana | `http://grafana.internal/d/threat-engine` | Dashboards |
| Prometheus | `http://prometheus.internal/alerts` | Active alerts |
| Jaeger | `http://jaeger-ui:16686` | Distributed traces |
| AlertManager | `http://alertmanager.internal` | Alert routing |

## Alert Reference

| Alert | Severity | Threshold | Action |
|-------|----------|-----------|--------|
| ScanFailureRateHigh | Critical | > 5% errors in 5m | Check credentials, DB, service health |
| ScanTimeoutDetected | Warning | P95 > 10min | Check rate limits, slow queries |
| VulnerabilityCacheTooOld | Warning | > 7 days | Trigger manual refresh |
| ThreatIntelCacheTooOld | Warning | > 3 days | Trigger manual refresh |
| ServiceNotReady | Critical | Down > 2min | Check pod, rollback, restart |
| DatabaseConnectionFailures | Critical | > 5 errors in 5m | Check RDS health, network |
| SlowETLTransformation | Warning | P95 > 5min | Add indexes, optimize queries |
| SlowFindingEvaluation | Warning | P95 > 2min | Simplify rules, reduce dataset |
