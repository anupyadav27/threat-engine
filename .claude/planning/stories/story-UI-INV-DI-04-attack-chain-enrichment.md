# Story DI-04: BFF Enrichment — `_enrich_attack_chain_steps()` in `threat_detail.py`

**Epic:** UI Investigation Journeys Sprint
**Status:** Ready for Dev
**Story Points:** 5
**Depends On:** None
**Blocks:** DI-07, DI-08

## Context

The Threat Detail page (`/threats/[threatId]`) has Attack Path and Blast Radius tabs that are currently dead because the BFF returns minimal data. The `_build_attack_path()` function discards path-level metadata and returns bare hop arrays with no enrichment. The `_build_blast_radius()` function omits four fields the frontend needs. The BFF also calls a non-existent `/api/v1/threat/{threat_id}/remediation` endpoint on every page load, causing a 404 error that delays the page. This story fixes all four BFF helper functions in `threat_detail.py`.

## Scope

Modify four functions in `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/threat_detail.py`:
1. `_build_attack_path()` — preserve path-level fields, add per-hop enrichment via new `_enrich_attack_chain_steps()`
2. Add new helpers `_enrich_attack_chain_steps()` and `_infer_resource_type_from_arn()`
3. `_build_blast_radius()` — add 4 missing fields
4. `_build_timeline()` — add `status_changed_at`/`status_changed_by` event support
5. `view_threat_detail()` — remove the `/remediation` engine call, derive SLA from severity

**Out of scope:** Frontend tab components (DI-07), NodeInvestigationPanel (DI-08), any engine changes.

## Files to Create/Modify

- `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/threat_detail.py` — multiple function changes (see Implementation Notes)

## Implementation Notes

### 1. `_infer_resource_type_from_arn(arn: str) -> str` — add new helper

```python
def _infer_resource_type_from_arn(arn: str) -> str:
    """Infer AWS resource type string from ARN.

    Args:
        arn: Full AWS ARN string or resource identifier.

    Returns:
        CloudFormation-style resource type string.
    """
    if not arn or not isinstance(arn, str):
        return "Unknown"
    a = arn.lower()
    if "instance/" in a:
        return "AWS::EC2::Instance"
    if "security-group/" in a:
        return "AWS::EC2::SecurityGroup"
    if arn.startswith("arn:aws:s3:::"):
        return "AWS::S3::Bucket"
    if "role/" in a:
        return "AWS::IAM::Role"
    if "user/" in a:
        return "AWS::IAM::User"
    if "function:" in a:
        return "AWS::Lambda::Function"
    if ":db:" in a:
        return "AWS::RDS::DBInstance"
    if ":secret:" in a:
        return "AWS::SecretsManager::Secret"
    if "key/" in a:
        return "AWS::KMS::Key"
    if "parameter/" in a:
        return "AWS::SSM::Parameter"
    # Generic fallback: extract service from arn:aws:{service}:...
    parts = arn.split(":")
    if len(parts) >= 3 and parts[0] == "arn":
        service = parts[2].title() if len(parts) > 2 else "Resource"
        return f"AWS::{service}::Resource"
    return "Unknown"
```

### 2. `_extract_short_name(arn: str) -> str` — add new helper

```python
def _extract_short_name(arn: str) -> str:
    """Extract a human-readable short name from an ARN.

    Prefers the last path segment after '/', then last ':' segment.

    Args:
        arn: Full ARN or resource identifier string.

    Returns:
        Short name string.
    """
    if not arn:
        return ""
    if "/" in arn:
        return arn.split("/")[-1]
    return arn.split(":")[-1]
```

### 3. `_enrich_attack_chain_steps(hops, attack_chain, threat_raw)` — add new function

```python
def _enrich_attack_chain_steps(
    hops: list,
    attack_chain: dict,
    threat_raw: dict,
) -> list:
    """Enrich raw attack chain hops with display-ready fields.

    Args:
        hops: List of hop dicts from attack_chain.hops JSONB.
        attack_chain: Full attack_chain dict (for target, entry_point).
        threat_raw: Raw threat dict from threat_detections table.

    Returns:
        List of enriched hop dicts.
    """
    target = attack_chain.get("target", "")
    entry_point = attack_chain.get("entry_point", "")

    # Extract first MITRE technique ID — handles both string list and object list
    techniques = threat_raw.get("mitre_techniques") or []
    first_technique = ""
    if techniques:
        first = techniques[0]
        if isinstance(first, dict):
            first_technique = first.get("id") or first.get("technique_id", "")
        else:
            first_technique = str(first)

    enriched = []
    for idx, hop in enumerate(hops):
        from_arn = hop.get("from") or hop.get("from_resource", "")
        to_arn = hop.get("to") or hop.get("to_resource", "")
        is_entry = idx == 0
        is_target = to_arn == target
        is_internet_reachable = is_entry and (not from_arn or from_arn.lower().startswith("internet"))

        enriched.append({
            "from": from_arn,
            "fromName": _extract_short_name(from_arn) if from_arn else "Internet",
            "fromResourceType": _infer_resource_type_from_arn(from_arn) if from_arn else "Internet",
            "to": to_arn,
            "toName": _extract_short_name(to_arn),
            "toResourceType": _infer_resource_type_from_arn(to_arn),
            "relationship": hop.get("rel") or hop.get("relationship", ""),
            "category": hop.get("category", ""),
            "technique": first_technique,
            "riskScore": threat_raw.get("risk_score", 0) if is_target else 0,
            "isTarget": is_target,
            "isEntry": is_entry,
            "isInternetReachable": is_internet_reachable,
        })
    return enriched
```

### 4. Replace `_build_attack_path()` — preserve path-level fields

**Current function (lines 119-145) returns only `{exists, steps}`.**

**Replace with:**
```python
def _build_attack_path(threat: dict, analysis: dict) -> dict:
    """Extract and enrich attack path from threat data and analysis.

    Preserves path-level metadata (chainType, pathScore, entryPoint, target,
    targetCategory) in addition to per-hop steps.

    JSONB note: attack_chain is already a dict — never call json.loads().
    """
    attack_chain = analysis.get("attack_chain")

    if attack_chain and isinstance(attack_chain, dict):
        hops = attack_chain.get("hops") or attack_chain.get("steps") or attack_chain.get("chain", [])
        enriched_steps = _enrich_attack_chain_steps(hops, attack_chain, threat)
        return {
            "exists": bool(enriched_steps),
            "chainType": attack_chain.get("chain_type", ""),
            "pathScore": attack_chain.get("path_score", 0),
            "entryPoint": attack_chain.get("entry_point", ""),
            "target": attack_chain.get("target", ""),
            "targetCategory": attack_chain.get("target_category", ""),
            "depth": attack_chain.get("depth", len(enriched_steps)),
            "steps": enriched_steps,
        }

    if attack_chain and isinstance(attack_chain, list):
        # Older format: list of hops directly
        enriched_steps = _enrich_attack_chain_steps(attack_chain, {}, threat)
        return {"exists": bool(enriched_steps), "chainType": "", "pathScore": 0,
                "entryPoint": "", "target": "", "targetCategory": "",
                "depth": len(enriched_steps), "steps": enriched_steps}

    # Fallback to threat-level data
    attack_path = threat.get("attack_path") or threat.get("attack_paths") or {}
    if isinstance(attack_path, list):
        steps = attack_path
    elif isinstance(attack_path, dict):
        steps = attack_path.get("steps") or attack_path.get("hops", [])
    else:
        steps = []

    enriched_steps = _enrich_attack_chain_steps(steps, attack_path if isinstance(attack_path, dict) else {}, threat)
    return {
        "exists": bool(enriched_steps),
        "chainType": attack_path.get("chain_type", "") if isinstance(attack_path, dict) else "",
        "pathScore": attack_path.get("path_score", 0) if isinstance(attack_path, dict) else 0,
        "entryPoint": attack_path.get("entry_point", "") if isinstance(attack_path, dict) else "",
        "target": attack_path.get("target", "") if isinstance(attack_path, dict) else "",
        "targetCategory": attack_path.get("target_category", "") if isinstance(attack_path, dict) else "",
        "depth": len(enriched_steps),
        "steps": enriched_steps,
    }
```

### 5. Update `_build_blast_radius()` — add 4 missing fields

**Current function (lines 148-179) returns `{reachableCount, criticalCount, criticalAssets, affectedServices}`.**

After the existing `criticalAssets` line, add:
```python
"depthDistribution": blast.get("depth_distribution", {}),
"reachableResources": blast.get("reachable_resources", [])[:50],
"pathEdges": blast.get("path_edges", []),
"isInternetReachable": blast.get("is_internet_reachable", False),
```

And enrich `criticalAssets` with `resourceName`:
```python
raw_critical = blast.get("critical_assets", [])
critical_assets = [
    {**a, "resourceName": _extract_short_name(a.get("resource_uid", "") or a.get("arn", ""))}
    if isinstance(a, dict) else {"resource_uid": str(a), "resourceName": _extract_short_name(str(a))}
    for a in raw_critical
]
```

Apply the same 4 fields to the fallback (threat-level blast_radius) block.

### 6. Update `_build_timeline()` — add `status_changed_at` events

**Current function (lines 207-227) reads `detected`, `last_seen`, `created`, `analysis_created`.**

Add status change event after the existing `analysis_created` block:
```python
# Add status-change events from threat_detections
status_changed_at = threat.get("status_changed_at")
status_changed_by = threat.get("status_changed_by")
if status_changed_at and status_changed_at not in (detected, created, last_seen):
    label = f"Status changed by {status_changed_by}" if status_changed_by else "Status changed"
    events.append({
        "timestamp": status_changed_at,
        "event": label,
        "type": "status_change",
        "actor": status_changed_by or "",
    })
```

### 7. Remove `/remediation` engine call from `view_threat_detail()`

**Current `fetch_many` call (lines 247-253):**
```python
results = await fetch_many([
    ("threat", f"/api/v1/threat/threats/{threat_id}", {"tenant_id": tenant_id}),
    ("threat", f"/api/v1/threat/analysis/{threat_id}", {"tenant_id": tenant_id}),
    ("threat", f"/api/v1/threat/detections/{threat_id}/check-findings", {"tenant_id": tenant_id}),
    ("threat", f"/api/v1/threat/{threat_id}/remediation", {"tenant_id": tenant_id}),  # REMOVE THIS
], auth_headers=fwd_headers)

threat_raw, analysis_raw, misconfig_raw, remediation_raw = results
```

**Replace with:**
```python
results = await fetch_many([
    ("threat", f"/api/v1/threat/threats/{threat_id}", {"tenant_id": tenant_id}),
    ("threat", f"/api/v1/threat/analysis/{threat_id}", {"tenant_id": tenant_id}),
    ("threat", f"/api/v1/threat/detections/{threat_id}/check-findings", {"tenant_id": tenant_id}),
], auth_headers=fwd_headers)

threat_raw, analysis_raw, misconfig_raw = results
```

Then replace `remediation_raw` usage (lines 264-313). Remove all `remediation_raw` references. Build remediation directly from `analysis_raw`:

```python
SLA_MAP = {"critical": "24h", "high": "72h", "medium": "30d", "low": "90d"}
severity = (threat_raw.get("severity") or "").lower()
sla_target = SLA_MAP.get(severity, "30d")

analysis_recs = analysis_raw.get("recommendations") or []
rem_steps = [
    {"action": r} if isinstance(r, str) else r
    for r in analysis_recs
]
sla = {"target": sla_target, "severity": severity}
```

**JSONB note:** `analysis_raw.get("recommendations")` is already a Python list — NEVER call `json.loads()`.

## Acceptance Criteria

- [ ] `_build_attack_path()` returns `chainType`, `pathScore`, `entryPoint`, `target`, `targetCategory` at path level (not just `exists` and `steps`)
- [ ] Each hop in `steps` has all 11 enriched fields: `from`, `fromName`, `fromResourceType`, `to`, `toName`, `toResourceType`, `relationship`, `category`, `technique`, `riskScore`, `isTarget`, `isEntry`, `isInternetReachable`
- [ ] First hop with empty `from` → `isInternetReachable: true`, `isEntry: true`, `fromName: "Internet"`
- [ ] Hop whose `to` equals `attack_chain.target` → `isTarget: true`, `riskScore` set to `threat_raw.risk_score`
- [ ] `mitre_techniques` dual form works: `["T1078"]` → `technique: "T1078"`; `[{"id":"T1078"}]` → `technique: "T1078"`
- [ ] `_build_blast_radius()` returns `depthDistribution`, `reachableResources` (max 50), `pathEdges`, `isInternetReachable`
- [ ] `criticalAssets` items have `resourceName` field derived from `resource_uid` or `arn`
- [ ] `_build_timeline()` includes status-change events with `type: "status_change"`
- [ ] BFF no longer calls `/api/v1/threat/{threat_id}/remediation` (verify by grepping the updated file)
- [ ] `remediation.sla.target` is `"24h"` when `severity="critical"`, `"72h"` for `"high"`, `"30d"` for `"medium"`, `"90d"` for `"low"`
- [ ] JSONB fields (`attack_chain`, `blast_radius`, `recommendations`) never passed through `json.loads()`
- [ ] All existing BFF tests pass (regression)

## Security Gates

- **B-5 (tenant scoping):** `tenant_id` passed to all three remaining `fetch_many` calls; resolved from `resolve_tenant_id(request)` not from query param
- **JSONB safety:** No `json.loads()` calls added in this change — psycopg2 auto-deserializes all JSONB columns

## Definition of Done

- [ ] Code written and passes linter
- [ ] All acceptance criteria verified
- [ ] `grep -n "remediation" shared/api_gateway/bff/threat_detail.py` no longer shows the engine call
- [ ] BFF contract tests updated if the `GET /api/v1/views/threats/{threat_id}` contract test exists
- [ ] bmad-security-reviewer approved (BFF endpoint change)
- [ ] bmad-qa acceptance test run