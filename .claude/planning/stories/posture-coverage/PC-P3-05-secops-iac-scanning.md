# Story PC-P3-05: SecOps Engine — Infrastructure-as-Code Scanning (Terraform + CloudFormation)

## Status: ready

## Metadata
- **Phase**: P3 — Tier C (requires IaC file access via git repos; separate scanner logic from existing SAST)
- **Sprint**: Posture Coverage Enhancement — Planning Track
- **Points**: 8
- **Priority**: P3
- **Depends on**: SecOps engine baseline (v-secops-findings1), git repo onboarding (SECOPS sprint)
- **RACI**: R=DEV A=DL C=SA I=PO
- **Security Gate**: bmad-security-architect + bmad-security-reviewer

## Gap Being Closed

**Current state:** SecOps engine does SAST (application code) and SCA (dependencies). IaC files (Terraform `.tf`, CloudFormation `.yaml/.json`, Pulumi, CDK) are present in the same repos but are ignored. Misconfigurations in IaC — the most common root cause of cloud security incidents — are not detected at the code level.

**Why IaC scanning matters:** If the Terraform that provisions an S3 bucket has `acl = "public-read"`, the check engine will flag the bucket after it's deployed. IaC scanning catches it before deployment — shift-left security.

**Why Tier C:** 
1. Requires a separate IaC rule catalog (different from SAST rules)
2. IaC parsing is non-trivial (Terraform HCL parser, CloudFormation template parser)
3. Need to map IaC findings back to deployed resources (IaC resource → actual cloud ARN)

## Technology Choice: tfsec / checkov (evaluated, use Checkov)

**Recommendation: [Checkov](https://github.com/bridgecrewio/checkov)** (Apache 2.0, Bridgecrew/Palo Alto)
- Supports Terraform, CloudFormation, Kubernetes YAML, Dockerfile, ARM, Bicep
- 1,000+ built-in policies
- Outputs JSON findings → easy integration into existing secops findings pipeline
- Can be run as a Python library (`checkov.main`) — no subprocess needed
- Active development; maps to CIS, NIST, PCI-DSS

**Alternative: tfsec** — Terraform-only; Go binary; faster but narrower coverage

## Implementation Plan

### 1. IaC Scanner Module

**New file:** `engines/secops/secops_engine/iac_scanner.py`

```python
class IaCScannerEngine:
    def scan_repo(self, repo_path: str, scan_run_id: str, tenant_id: str) -> List[IaCFinding]:
        # Run checkov on detected IaC files
        # Parse JSON output into IaCFinding objects
        # Map checkov check_ids to our severity + rule_id
```

**Finding detection:** Walk repo directory tree, detect by extension:
- `*.tf` → Terraform
- `*.cfn.yaml`, `*cloudformation*.yaml`, `template.yaml` → CloudFormation
- `kubernetes/*.yaml`, `k8s/*.yaml` → Kubernetes manifests
- `Dockerfile*` → Docker (already handled by secops, skip)

### 2. New Findings Table

**New migration:** `shared/database/migrations/026_iac_findings.sql`
```sql
-- In threat_engine_secops DB
CREATE TABLE IF NOT EXISTS iac_findings (
    finding_id      VARCHAR(32)  PRIMARY KEY,
    scan_run_id     UUID         NOT NULL,
    tenant_id       VARCHAR(255) NOT NULL,
    repo_uid        VARCHAR(1024),  -- git remote URL + branch
    iac_type        VARCHAR(50),    -- terraform / cloudformation / kubernetes
    file_path       VARCHAR(1024),
    line_start      INTEGER,
    line_end        INTEGER,
    check_id        VARCHAR(100),   -- checkov check ID e.g. CKV_AWS_18
    rule_id         VARCHAR(255),   -- our rule_id for RBAC/UI
    severity        VARCHAR(20),
    status          VARCHAR(10) DEFAULT 'FAIL',
    resource_type   VARCHAR(255),   -- IaC resource type e.g. aws_s3_bucket
    resource_name   VARCHAR(512),   -- IaC logical name
    description     TEXT,
    remediation     TEXT,
    framework_refs  JSONB,          -- {CIS: "...", NIST: "..."}
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_iac_tenant_scan ON iac_findings (tenant_id, scan_run_id);
```

### 3. IaC Resource → Cloud Resource Mapping

The holy grail: link `aws_s3_bucket.my_bucket` (IaC) to `arn:aws:s3:::my-bucket` (deployed). Approach:
- Parse Terraform state files (`.tfstate`) if available in repo
- Map CloudFormation logical ID to Physical ID via CloudFormation Stack describe
- If no mapping found: flag IaC finding standalone (pre-deploy risk) without posture row

### 4. Posture Signal (when mapping exists)

When IaC resource maps to a deployed cloud resource:
```sql
-- Extend resource_security_posture:
ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS iac_misconfiguration_count  INTEGER  NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS iac_critical_count          INTEGER  NOT NULL DEFAULT 0;
```

## Acceptance Criteria

- [ ] AC-1: Checkov runs against a connected GitHub repo containing Terraform files → IaC findings inserted into `iac_findings` table
- [ ] AC-2: `check_id` mapped correctly to our `severity` taxonomy (checkov HIGH → our CRITICAL for open-to-internet, HIGH for encryption gaps)
- [ ] AC-3: IaC findings appear in SecOps findings API: `GET /api/v1/secops/findings?finding_type=iac`
- [ ] AC-4: When Terraform state file is present, `resource_name` in `iac_findings` maps to actual cloud resource ARN (stored in `resource_uid`)
- [ ] AC-5: `iac_misconfiguration_count > 0` in posture table for cloud resources with mapped IaC misconfigs
- [ ] AC-6: Checkov runs in subprocess isolation — if it crashes, secops SAST scan is unaffected
- [ ] AC-7: New image: `yadavanup84/secops-scanner:v-secops-iac1`

## Prerequisites

- [ ] PRE-1: Checkov added to `engines/secops/requirements.txt`
- [ ] PRE-2: Git repo onboarding (SECOPS sprint) must be complete — IaC scanner reads from already-cloned repo
- [ ] PRE-3: Migration 026 applied
- [ ] PRE-4: CloudFormation Stack API permissions added to discovery IAM role (for resource mapping)

## Definition of Done
- [ ] `iac_scanner.py` implemented with Checkov integration
- [ ] Migration 026 applied
- [ ] IaC findings visible in SecOps API and UI
- [ ] Posture columns updated when IaC→cloud mapping exists
- [ ] Checkov version pinned in requirements.txt (no `latest`)
