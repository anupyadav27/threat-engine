# Story PC-P1-06: IAM Engine — Compute reachable_pii_store_count Cross-Engine Signal

## Status: done

## Metadata
- **Phase**: P1 — Tier A (all data available in posture table after IAM + DataSec both run)
- **Sprint**: Posture Coverage Enhancement
- **Points**: 3
- **Priority**: P1
- **Depends on**: AP-P0-03 (IAM + DataSec both write to posture table)
- **Blocks**: PC-P1-07 (composite flags — admin_role_without_mfa uses this)
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-reviewer — cross-engine posture join is a new read pattern

## Gap Being Closed

**Current state:** `reachable_pii_store_count` column in `resource_security_posture` is always 0. The `can_access_pii` boolean on IAM resources tells us *whether* a role can access PII — but not *how many* PII stores. The attack-path crown jewel classifier cannot score "this role can reach 15 PII data stores" vs "this role can reach 1."

**Why Tier A:** After both IAM engine and DataSec engine run their posture writers, `resource_security_posture` already has:
- IAM resources: `can_access_pii=TRUE/FALSE`
- DataSec resources: `data_classification IN ('pii','phi','pci')`

The count is a self-join on the posture table — no new external data needed.

## Logic

This is a **second-pass enrichment** in the IAM posture writer, run after the primary IAM signal write. It queries the posture table (inventory DB) directly:

```sql
-- For each IAM resource that can_access_pii=TRUE,
-- count how many data resources in the same tenant+scan have PII classification
UPDATE resource_security_posture rsp_iam
SET reachable_pii_store_count = (
    SELECT COUNT(*)
    FROM resource_security_posture rsp_data
    WHERE rsp_data.tenant_id = rsp_iam.tenant_id
      AND rsp_data.scan_run_id = rsp_iam.scan_run_id
      AND rsp_data.data_classification IN ('pii', 'phi', 'pci', 'restricted')
)
WHERE rsp_iam.tenant_id = %s
  AND rsp_iam.scan_run_id = %s
  AND rsp_iam.can_access_pii = TRUE;
```

**Timing constraint:** This second pass must run AFTER DataSec's posture writer has committed. Since IAM and DataSec run in parallel (stage 5), the safest approach is:
- Keep the existing IAM primary write as-is
- Add the `reachable_pii_store_count` enrichment as a **new step in run_scan.py** with a 60-second wait + retry loop that checks if any DataSec posture rows exist for this `scan_run_id` before running the UPDATE

Alternatively: move this enrichment into the **attack-path engine** (stage 6.5) since it runs after all stage-5 engines. Either approach is acceptable — document the choice in a comment.

## Implementation Options

**Option A (recommended):** Move `reachable_pii_store_count` enrichment to attack-path engine stage 6.5. It's a pure posture table UPDATE with no engine DB dependency. Clean separation: attack-path engine is already responsible for writing composite signals.

**Option B:** Add retry loop in IAM engine posture writer. Simple but fragile — if DataSec is slow, the count will be 0.

Story implementer should choose Option A and update this story's AC if agreed.

## Acceptance Criteria

- [ ] AC-1: After a full pipeline run (IAM + DataSec both complete), `reachable_pii_store_count > 0` for IAM roles with `can_access_pii=TRUE`
- [ ] AC-2: `reachable_pii_store_count = 0` for IAM roles with `can_access_pii=FALSE` — no spurious update
- [ ] AC-3: The count reflects DataSec-classified resources for the SAME `scan_run_id` only (multi-tenant isolation)
- [ ] AC-4: If DataSec has not yet run for this scan, `reachable_pii_store_count` stays at 0 (no error, no crash)
- [ ] AC-5: Implementation approach (A or B) is documented in a code comment

## Definition of Done
- [ ] `reachable_pii_store_count` UPDATE logic implemented (in attack-path engine or IAM engine as decided)
- [ ] Post-deploy: `SELECT resource_uid, can_access_pii, reachable_pii_store_count FROM resource_security_posture WHERE can_access_pii=TRUE LIMIT 5` shows count > 0