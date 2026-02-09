# Performance Tuning

> Optimization guide for database, scanning, graph operations, and Kubernetes scaling.

---

## Database Performance

### Connection Pooling

```bash
DB_POOL_SIZE=10          # Connections per engine
DB_MAX_OVERFLOW=20       # Burst connections
DB_POOL_TIMEOUT=30       # Wait timeout (seconds)
DB_POOL_RECYCLE=3600     # Recycle connections (seconds)
```

**Recommendations:**
- Production: `DB_POOL_SIZE=20`, `DB_MAX_OVERFLOW=40`
- Each engine instance maintains its own pool
- Total connections = (pool_size + max_overflow) x engine_instances

### Key Indexes

```sql
-- threat_detections: query by tenant + scan
CREATE INDEX idx_threat_det_tenant_scan ON threat_detections(tenant_id, scan_id);
CREATE INDEX idx_threat_det_severity ON threat_detections(severity);

-- check_findings: query by scan + rule
CREATE INDEX idx_check_findings_scan ON check_findings(check_scan_id, tenant_id);
CREATE INDEX idx_check_findings_resource ON check_findings(resource_uid);

-- inventory_findings: query by tenant + type
CREATE INDEX idx_inventory_tenant_type ON inventory_findings(tenant_id, resource_type);

-- rule_metadata: query by rule_id
CREATE INDEX idx_rule_metadata_rule_id ON rule_metadata(rule_id);
```

### JSONB Performance
- Use `?|` operator for array overlap (faster than extracting and comparing)
- Create GIN indexes on frequently queried JSONB columns:
```sql
CREATE INDEX idx_mitre_tech ON threat_detections USING gin(mitre_techniques);
```

---

## Scanning Performance

### Discovery Engine

| Setting | Default | Optimized | Description |
|---------|---------|-----------|-------------|
| `MAX_DISCOVERY_WORKERS` | 50 | 30-50 | Parallel service discovery threads |
| `MAX_SERVICE_WORKERS` | 10 | 5-10 | Workers per service |
| `MAX_REGION_WORKERS` | 5 | 3-5 | Workers per region |
| `BOTO_MAX_POOL_CONNECTIONS` | 100 | 50-100 | AWS API connection pool |
| `OPERATION_TIMEOUT` | 600 | 300-600 | Per-operation timeout (seconds) |

**Tips:**
- Reduce workers if hitting AWS API rate limits
- Use `BOTO_RETRY_MODE=adaptive` for automatic backoff
- Scan specific services instead of all: `"services": ["s3", "iam", "ec2"]`

### Check Engine

| Setting | Default | Optimized | Description |
|---------|---------|-----------|-------------|
| `MAX_CHECK_WORKERS` | 50 | 30-50 | Parallel check threads |
| `FOR_EACH_MAX_WORKERS` | 50 | 30 | Workers for for-each operations |

**Tips:**
- Check engine is CPU-bound (rule evaluation)
- Increase CPU limits in K8s for faster checks
- Rule evaluation is parallelized per service

---

## Graph Performance (Neo4j)

### Build Optimization
- Current build time: ~3-5 minutes for ~1,855 nodes
- Use `UNWIND` for batch node creation
- Clear graph before rebuild: `MATCH (n) DETACH DELETE n`

### Query Optimization
- Limit `max_hops` in attack path queries (default 5, max 10)
- Use specific labels: `MATCH (b:S3Bucket)` not `MATCH (n:Resource)`
- Add indexes on frequently queried properties:
```cypher
CREATE INDEX FOR (r:Resource) ON (r.uid);
CREATE INDEX FOR (r:Resource) ON (r.tenant_id);
CREATE INDEX FOR (t:ThreatDetection) ON (t.severity);
```

### Neo4j Aura Limits
- Free tier: 200K nodes, 400K relationships
- Professional: Higher limits
- Monitor with: `CALL db.stats.retrieve("STORE")` (if available)

---

## Kubernetes Scaling

### Horizontal Pod Autoscaler

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: core-engine-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: core-engine
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

### Resource Limits (Production)

| Engine | Memory | CPU | Replicas |
|--------|--------|-----|----------|
| API Gateway | 256Mi-512Mi | 250m-500m | 2-10 |
| Core Engine | 2Gi-4Gi | 1-2 | 2-10 |
| Threat Engine | 512Mi-2Gi | 250m-1000m | 1-3 |
| Compliance | 256Mi-1Gi | 250m-500m | 1-3 |
| Inventory | 256Mi-1Gi | 250m-500m | 1-2 |
| Others | 256Mi-512Mi | 250m-500m | 1 |

---

## Caching

### Redis Usage
- Celery task queue (admin/user portal)
- Session storage (Django apps)
- Not currently used for API response caching

### Potential Cache Points
1. Rule metadata (changes infrequently) — cache in memory
2. Compliance framework definitions — cache in memory
3. Graph summary statistics — cache with 5-min TTL
4. Tenant information — cache in memory

---

## Benchmarks (Typical)

| Operation | Duration | Data Volume |
|-----------|----------|-------------|
| Discovery scan (all services) | 2-5 min | 280 resources |
| Check scan | 30-60 sec | 764 findings |
| Inventory build | 15-30 sec | 280 assets |
| Threat detection | 5-10 sec | 21 threats |
| Threat analysis | 2-5 sec | 21 analyses |
| Graph build | 3-5 min | 1,855 nodes |
| Attack path query | 0.5-2 sec | 23 paths |
| Blast radius query | 0.5-1 sec | 4 reachable |
| Compliance report | 10-30 sec | 7 frameworks |
