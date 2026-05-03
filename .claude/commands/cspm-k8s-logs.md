# /cspm-k8s-logs

Stream or retrieve logs from a CSPM engine pod.

## Usage
```
/cspm-k8s-logs <engine-name>
/cspm-k8s-logs <engine-name> --tail 200
/cspm-k8s-logs <engine-name> --previous
```

## Commands

```bash
# Tail live logs
kubectl logs -f -l app=engine-<name> -n threat-engine-engines --tail=100

# Recent logs (no follow)
kubectl logs -l app=engine-<name> -n threat-engine-engines --tail=200

# Previous pod (crashed pod)
kubectl logs -l app=engine-<name> -n threat-engine-engines --previous --tail=100

# Scanner job logs (for discovery/inventory/check/threat)
kubectl logs -l job-name=<job-name> -n threat-engine-engines --tail=200

# Specific pod
kubectl logs <pod-name> -n threat-engine-engines --tail=200
```

## What to look for in logs

**Discovery:** `"scan complete"`, `"0 findings"` → credential issue or service disabled
**Check:** `"rule_discoveries loaded"`, `"0 rules matched"` → check is_active in DB
**Threat:** `"Neo4j connection"`, `"0 threat findings"` → check tenants upsert
**Compliance:** `"compliance_report inserted"`, `"0 controls"` → check compliance_rule_data_mapping
**IAM:** `"iam_scan completed"`, `"57 rules"` → confirm rule count
**Network:** `"Layer 1 findings"`, `"Layer 2 topology"` → confirm both phases ran
**Risk:** `"Stage 1 ETL"`, `"Stage 2 FAIR"`, `"Stage 3 aggregation"` → confirm 3 stages
