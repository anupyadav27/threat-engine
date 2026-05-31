# CDR-3-S03: Attack-Path Finding Detail Shows Contributing CDR Findings

## Sprint
CDR-3 — Attack-Path Enrichment Sprint

## Priority
P1 — When a security analyst opens an attack path finding, they see the path score and hops but not WHY CDR elevated the score. The ×1.50 CDR multiplier is invisible — there is no link between an attack path and the CDR findings that contributed to its score.

## Depends On
CDR-1-S01 (OBSERVED_ACCESS edges) and CDR-3-S01 (attack-path traversal via OBSERVED_ACCESS) should be deployed for maximum value, but this story can be partially implemented using `security_findings` cross-reference even before those stories.

## Story
As a security analyst viewing an attack path detail panel, I need to see which CDR behavioral detections contributed to this path's score, so I can understand whether the path is theoretical (high score from misconfigs) or confirmed active (high score from observed CDR behavior).

## Background

When attack-path scorer applies the ×1.50 CDR multiplier, it reads `has_active_cdr_actor=TRUE` from `resource_security_posture`. The resource_uid of that posture row links to CDR findings in `security_findings` where `source_engine='cdr'` and `resource_uid=<same>`.

The attack-path engine currently does NOT store which CDR findings contributed to a path's score. This story adds that linkage.

**Implementation approach:**
1. During scoring, collect the `source_finding_id` values from `security_findings` where CDR multiplier was applied
2. Store them in `attack_paths.path_metadata` JSONB under key `contributing_cdr_finding_ids`
3. BFF attack-path view fetches those finding details from the CDR engine to display in the detail panel

## Files to Read First

- `engines/attack-path/attack_path_engine/core/scorer.py` — where `has_active_cdr_actor` is read and multiplier applied; this is where to collect finding IDs
- `engines/attack-path/attack_path_engine/db/writer.py` — how `attack_paths` rows are written; check `path_metadata` JSONB column
- `engines/attack-path/attack_path_engine/run_scan.py` — how `findings_lookup` (Dict[resource_uid → findings]) is passed to scorer
- `shared/api_gateway/bff/` — find the attack-path BFF view (likely `bff/attack_path.py` or similar); check detail response shape
- `engines/cdr/cdr_engine/api_server.py` — `GET /api/v1/cdr/findings/by-resource` endpoint (already exists for asset-context enrichment)

## Files to Modify

| File | Change |
|---|---|
| `engines/attack-path/attack_path_engine/core/scorer.py` | Collect CDR `source_finding_id` values when multiplier is applied; return them alongside path score |
| `engines/attack-path/attack_path_engine/db/writer.py` | Store `contributing_cdr_finding_ids` list in `path_metadata` JSONB |
| `shared/api_gateway/bff/attack_path.py` (or equivalent) | On path detail fetch, read `contributing_cdr_finding_ids` from `path_metadata`, fetch finding summaries from CDR engine, include in response |
| `frontend/src/app/(portal)/attack-path/` | Add "CDR Evidence" section to attack path detail panel |

## Exact Scorer Change

In `scorer.py`, where the CDR multiplier is applied (pseudo-code based on current pattern):

```python
contributing_cdr_ids = []

for hop_resource_uid in path_hops:
    posture = posture_lookup.get(hop_resource_uid, {})
    if posture.get("has_active_cdr_actor"):
        hop_score *= 1.50
        # Collect contributing CDR findings
        cdr_findings = findings_lookup.get(hop_resource_uid, {}).get("threat_detections", [])
        for f in cdr_findings:
            if f.get("source_engine") == "cdr" and f.get("source_finding_id"):
                contributing_cdr_ids.append(f["source_finding_id"])

# Return contributing IDs alongside final path score
return final_score, list(set(contributing_cdr_ids))
```

### Writer change

In `writer.py`, when building the `path_metadata` JSONB dict, add:
```python
path_metadata["contributing_cdr_finding_ids"] = contributing_cdr_ids[:10]  # cap at 10
```

### BFF change

In the attack-path detail handler, after fetching the path from DB:
```python
cdr_ids = path.get("path_metadata", {}).get("contributing_cdr_finding_ids", [])
if cdr_ids:
    # Fetch CDR finding summaries
    cdr_summaries = await fetch_cdr_findings_by_ids(cdr_ids, auth_headers)
else:
    cdr_summaries = []

# Add to response
response["cdrEvidence"] = {
    "findings": cdr_summaries,
    "count": len(cdr_summaries),
    "elevatedScore": len(cdr_summaries) > 0,
}
```

Use CDR engine endpoint `GET /api/v1/cdr/findings?finding_ids=id1,id2,...` (add this to CDR engine if not present) or `GET /api/v1/cdr/findings/by-resource` per resource_uid.

## UI: CDR Evidence Section in Attack Path Detail Panel

```
┌─────────────────────────────────────────────────────────┐
│  Attack Path Score: 87  🔴 CRITICAL                     │
│  ─────────────────────────────────────────────────────  │
│  Path Hops: EC2 → IAM Role → S3                         │
│                                                         │
│  CDR Evidence  (2 active detections elevating score)    │
│  ┌────────────────────────────────────────────────────┐ │
│  │ 🔴 Anomalous API rate — arn:aws:iam::.../alice     │ │
│  │    T1078 · 14 min ago · HIGH                       │ │
│  │ 🟡 Cross-region access — arn:aws:s3:::prod         │ │
│  │    T1530 · 22 min ago · MEDIUM                     │ │
│  └────────────────────────────────────────────────────┘ │
│  These detections applied a 1.5× score multiplier.      │
└─────────────────────────────────────────────────────────┘
```

- Section shown only when `cdrEvidence.count > 0`
- Each CDR finding shown as: severity icon, title, actor/resource short name, MITRE technique, age, severity
- Click finding → opens CDR finding detail side panel (not navigate away)
- Footer text explains multiplier: "These detections applied a 1.5× score multiplier"
- If no CDR evidence: section not rendered (not an empty state)

## Acceptance Criteria

- [ ] `attack_paths.path_metadata` JSONB contains `contributing_cdr_finding_ids` array after scorer runs
- [ ] Array is capped at 10 IDs per path
- [ ] BFF attack-path detail response includes `cdrEvidence.findings` array
- [ ] `cdrEvidence.findings` contains finding title, severity, mitre_technique_id, first_seen_at
- [ ] UI renders "CDR Evidence" section when findings present
- [ ] UI section hidden when no CDR evidence (path scored on misconfigs alone)
- [ ] Paths with no CDR multiplier applied: `contributing_cdr_finding_ids = []` (empty, not null)
- [ ] All cross-engine BFF calls include X-Auth-Context header (CDR engine requires it)
- [ ] `require_permission('cdr:read')` checked — viewer can see CDR evidence in attack path detail

## Security Checklist

- [ ] CDR finding IDs fetched by BFF using internal service credentials, not user-supplied IDs
- [ ] `tenant_id` validated on CDR finding fetch — no cross-tenant finding leak
- [ ] `contributing_cdr_finding_ids` capped at 10 — no unbounded array in JSONB

## Definition of Done

- [ ] Scorer collects and returns CDR finding IDs
- [ ] Writer stores them in `path_metadata`
- [ ] BFF fetches and includes `cdrEvidence` in attack-path detail response
- [ ] Frontend renders CDR Evidence section in attack path detail panel
- [ ] Manual verify: test-tenant-002 attack path with CDR actor → detail panel shows contributing CDR findings
- [ ] Attack-path image rebuilt and deployed (use `kubectl set image` — linter revert risk)
- [ ] Gateway image rebuilt if BFF changed