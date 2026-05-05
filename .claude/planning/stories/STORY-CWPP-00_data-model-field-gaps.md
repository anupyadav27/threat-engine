# STORY-CWPP-00: CWPP Data Model Field Gaps — Field Aliases + CVE Crosswalk Architecture

## Track
CWPP Investigation Journey — Pre-Sprint (Must ship before STORY-CWPP-01 and STORY-CWPP-02)

## Priority
P1 — UI renders incorrect or empty data without these fixes. No DB migrations needed — all Python layer.

## Context

A specialist CWPP engine agent audited all 5 workload handlers against the finalized UI spec. Unlike CIEM, CWPP has **no hard schema blockers** — all gaps are field aliasing, per-row annotation from aggregate data already in memory, and one architectural decision (CVE crosswalk). Container-security engine needs 2 query extensions.

---

## Part A — CWPP Workload Handler Fixes (Pure Python, no DB)

### 1. `containers.py` — Field aliases and per-domain score

**File**: `engines/cwpp/cwpp_engine/workloads/containers.py`

```python
# When building clusters list from container_sec_inventory rows:
cluster = {
    "cluster_name":   item.get("resource_name"),           # UI needs cluster_name
    "provider":       item.get("provider"),
    "region":         item.get("region"),
    "is_public":      item.get("endpoint_public", False),  # UI needs is_public bool
    "security_score": item.get("posture_score", 0),
    "finding_count":  item.get("failed_checks", 0),        # failed_checks = best proxy
    "resource_uid":   item.get("resource_uid"),
}

# After receiving domain_breakdown rows from container-security, compute score:
for domain in domain_breakdown:
    total = domain.get("total", 0)
    pass_count = domain.get("pass_count", 0)
    domain["score"] = round((pass_count / total) * 100) if total > 0 else 0
```

### 2. `hosts.py` — Field aliases, per-CVE affected host count, middleware type annotation

**File**: `engines/cwpp/cwpp_engine/workloads/hosts.py`

```python
# Add to summary dict:
summary["total_findings"]        = total_vulns   # alias — workload card normalizer reads this
summary["vulnerable_components"] = sbom_summary.get("total_vulnerabilities", 0)  # alias

# When building os_vulns list:
os_vuln = {
    "cve_id":       v.get("cve_id"),
    "package_name": v.get("package_name"),
    "version":      v.get("package_version"),  # rename from package_version
    "cvss_score":   v.get("score"),            # rename from score (COALESCE best CVSS)
    "severity":     v.get("severity"),
    "resource_uid": v.get("resource_uid") or v.get("asset_id"),
}

# Annotate affected_hosts_count per CVE (Python Counter, no extra query):
from collections import Counter
cve_host_counts = Counter(v["cve_id"] for v in all_vulns if v.get("cve_id"))
for os_vuln in os_vulns:
    os_vuln["affected_hosts_count"] = cve_host_counts.get(os_vuln["cve_id"], 1)

# Annotate middleware_type per middleware vuln row:
MIDDLEWARE_KEYWORDS = {
    "tomcat": "tomcat", "nginx": "nginx", "iis": "iis", "kafka": "kafka",
    "jboss": "jboss", "wildfly": "jboss", "weblogic": "weblogic",
    "jetty": "jetty", "apache": "apache", "openssl": "openssl",
    "log4j": "log4j", "spring": "spring"
}
def _get_middleware_type(package_name: str) -> str:
    pkg_lower = (package_name or "").lower()
    for kw, label in MIDDLEWARE_KEYWORDS.items():
        if kw in pkg_lower:
            return label
    return "other"

for mw in middleware_vulns:
    mw["middleware_type"] = _get_middleware_type(mw.get("package_name", ""))
```

### 3. `serverless.py` — Per-function flags derivation

**File**: `engines/cwpp/cwpp_engine/workloads/serverless.py`

```python
from collections import Counter

DEPRECATED_RUNTIMES = {
    "python2.7", "python3.6", "nodejs8.10", "nodejs10.x", "nodejs12.x",
    "nodejs14.x", "dotnetcore2.1", "dotnetcore3.1", "ruby2.5", "java8"
}

# Build per-function metadata from findings in memory:
finding_count_by_uid = Counter(f.get("resource_uid") for f in serverless_findings)
iam_finding_uids = {
    f["resource_uid"] for f in serverless_findings
    if any(kw in (f.get("rule_id","") + f.get("title","")).lower()
           for kw in ["iam", "role", "permission", "policy"])
}

# Build functions list:
functions = []
for item in serverless_inventory:
    runtime = item.get("finding_data", {}).get("Runtime", "unknown")
    functions.append({
        "function_name":          item.get("resource_name"),
        "runtime":                runtime,
        "region":                 item.get("region"),
        "account_id":             item.get("account_id"),
        "provider":               item.get("provider"),
        "resource_uid":           item.get("resource_uid"),
        "has_public_url":         bool(item.get("finding_data", {}).get("FunctionUrlConfig")),
        "has_deprecated_runtime": runtime in DEPRECATED_RUNTIMES,
        "has_overpermissive_role": item.get("resource_uid") in iam_finding_uids,
        "finding_count":          finding_count_by_uid.get(item.get("resource_uid"), 0),
    })
```

### 4. `runtime.py` — Per-finding security flag derivation

**File**: `engines/cwpp/cwpp_engine/workloads/runtime.py`

```python
def _is_privileged(f: dict) -> bool:
    return "privileged" in (f.get("rule_id","") + f.get("title","")).lower()

def _is_host_network(f: dict) -> bool:
    return "hostnetwork" in (f.get("rule_id","") + f.get("title","")).lower()

def _is_host_pid(f: dict) -> bool:
    return "hostpid" in (f.get("rule_id","") + f.get("title","")).lower()

# Build privileged_containers list:
privileged_containers = []
for f in runtime_findings:
    if _is_privileged(f) or _is_host_network(f) or _is_host_pid(f):
        privileged_containers.append({
            "resource_uid":   f.get("resource_uid"),
            "container_name": f.get("finding_data", {}).get("container_name",
                              f.get("resource_name", "")),
            "namespace":      f.get("finding_data", {}).get("namespace", ""),
            "cluster_name":   f.get("cluster_name", ""),
            "privileged":     _is_privileged(f),
            "host_network":   _is_host_network(f),
            "host_pid":       _is_host_pid(f),
            "seccomp_status": "unknown",   # not derivable from rule_id alone
            "severity":       f.get("severity"),
            "rule_id":        f.get("rule_id"),
        })
```

---

## Part B — Container-Security Engine Changes (2 query extensions, requires rebuild)

**File**: `engines/container-security/container_security_engine/api/ui_data_router.py`

### Change 1: Add severity counts and resources_affected to domain_breakdown query

Find the domain_breakdown GROUP BY query. Extend SELECT:
```sql
COUNT(*) FILTER (WHERE severity = 'CRITICAL' AND status = 'FAIL') AS critical_count,
COUNT(*) FILTER (WHERE severity = 'HIGH' AND status = 'FAIL') AS high_count,
COUNT(DISTINCT resource_uid) AS resources_affected
```

### Change 2: Store `container_name` and `namespace` in finding_data for pod-security findings

In AWS/Azure/GCP provider pod-security finding creation, add to `finding_data` JSONB:
```python
finding_data.update({
    "container_name": pod_spec.get("container_name", ""),
    "namespace":      pod_spec.get("namespace", "default"),
})
```

---

## Part C — BFF: Radar Delta + CVE Crosswalk

**File**: `shared/api_gateway/bff/cwpp.py`

### 1. Surface `scan_trend` for radar delta (containers axis only)

The container-security engine already returns `scan_trend[]` (8 scans with `pass_rate`). The BFF drops this. Add to BFF response:

```python
containers_trend = containers_data.get("scan_trend", [])
"containers": {
    ...existing fields...,
    "scanTrend":        containers_trend,
    "priorPostureScore": containers_trend[-2]["pass_rate"]
                         if len(containers_trend) >= 2 else None,
}
```

The radar chart uses `priorPostureScore` for the containers axis delta only. Other axes show `—` (no prior data store without a CWPP DB).

### 2. CVE crosswalk — Two-track architecture (no new engine calls)

Add BFF view `GET /api/v1/views/cwpp/cve-crosswalk?scan_run_id=X`.

**Why two tracks** (from CWPP audit): Container/serverless/runtime rules are K8s and cloud-config posture checks with no CVE mapping. Joining them with host OS CVEs would be semantically incorrect. Two tracks: config issues (grouped by rule_id) and vulnerabilities (grouped by cve_id).

```python
from collections import defaultdict

# Track A: config issues across workloads (rule_id-based)
rule_crosswalk = defaultdict(lambda: {
    "workload_types": set(), "affected_resources": 0,
    "severity": "low", "mitre_technique": "", "title": ""
})
for wtype in ["containers", "images", "serverless", "runtime"]:
    for f in workload_data[wtype].get("findings", []):
        key = f["rule_id"]
        rule_crosswalk[key]["workload_types"].add(wtype)
        rule_crosswalk[key]["affected_resources"] += 1
        rule_crosswalk[key]["title"] = f.get("title", key)
        rule_crosswalk[key]["mitre_technique"] = f.get("mitre_technique", "")
        # keep max severity
        rule_crosswalk[key]["severity"] = max(
            rule_crosswalk[key]["severity"], f.get("severity","low"),
            key=lambda s: {"critical":4,"high":3,"medium":2,"low":1}.get(s,0)
        )

# Track B: CVE vulnerabilities (cve_id-based, hosts only for now)
cve_crosswalk = {}
all_host_vulns = (workload_data.get("hosts", {}).get("os_vulnerabilities", []) +
                  workload_data.get("hosts", {}).get("middleware_vulnerabilities", []))
for v in all_host_vulns:
    cid = v.get("cve_id", "")
    if cid:
        cve_crosswalk[cid] = {
            "workload_types": ["hosts"],  # images pending Trivy/Grype
            "severity":       v.get("severity"),
            "cvss_score":     v.get("cvss_score"),
            "epss_score":     None,       # Sprint 3
            "affected_resources": v.get("affected_hosts_count", 1),
        }

return {
    "configurationCrosswalk": [
        {"id": rid, "type": "config", **{**v, "workload_types": list(v["workload_types"])}}
        for rid, v in rule_crosswalk.items()
    ],
    "cveCrosswalk": [
        {"id": cid, "type": "cve", **v}
        for cid, v in cve_crosswalk.items()
    ]
}
```

---

## Acceptance Criteria

### Containers workload
- [ ] Cluster rows include `cluster_name`, `is_public` (bool), `security_score`, `finding_count`
- [ ] `domain_breakdown` rows include `score` (0-100), `critical_count`, `high_count`, `resources_affected`

### Hosts workload
- [ ] OS CVE rows include `version` (was `package_version`), `cvss_score` (was `score`), `affected_hosts_count`
- [ ] Middleware CVE rows include `middleware_type` label (tomcat/nginx/etc)
- [ ] SBOM summary includes `vulnerable_components` alias
- [ ] Summary includes `total_findings` alias (same value as `total_vulnerabilities`)

### Serverless workload
- [ ] Function rows include `function_name`, `runtime`, `has_public_url` (bool), `has_deprecated_runtime` (bool), `has_overpermissive_role` (bool), `finding_count`
- [ ] Deprecated runtime functions have `has_deprecated_runtime: true`
- [ ] No functions list is empty when `serverless_inventory` is non-empty

### Runtime workload
- [ ] Privileged container rows include `privileged`, `host_network`, `host_pid` booleans derived from rule_id
- [ ] `container_name` and `namespace` populated from `finding_data` (empty string gracefully if absent)
- [ ] `seccomp_status` is `"unknown"` per row — do not show fabricated value

### BFF
- [ ] `data.containers.priorPostureScore` is a number or `null` — never undefined
- [ ] `GET /views/cwpp/cve-crosswalk` returns `configurationCrosswalk[]` and `cveCrosswalk[]`
- [ ] `cveCrosswalk[].epss_score` is `null` — not an error, Sprint 3 field

### Container-Security Engine
- [ ] `domain_breakdown` includes `critical_count`, `high_count`, `resources_affected`
- [ ] Container-security image rebuilt and deployed before CWPP-01/02 sprint

## Security Checklist
- [ ] CVE crosswalk aggregation is tenant-scoped (data arrives pre-scoped from source engines)
- [ ] `has_public_url` derived from `finding_data.FunctionUrlConfig` — not from user input
- [ ] No SQL constructed from `rule_id`, `cve_id`, or `package_name` values — all Python Counter/dict
- [ ] `epss_score: null` is an honest null — add a `_note` field: `"epss_note": "EPSS not yet ingested — Sprint 3"`

## Definition of Done
- [ ] All CWPP handler fixes committed
- [ ] Container-security engine rebuilt with extended domain_breakdown query
- [ ] BFF `/views/cwpp/cve-crosswalk` endpoint live
- [ ] Manual verify: CWPP dashboard response has `cluster.is_public`, `function.has_deprecated_runtime`, `domain.resources_affected`
- [ ] Manual verify: cve-crosswalk returns separate `configurationCrosswalk` and `cveCrosswalk` arrays
