# Sprint: Posture Coverage Enhancement (PC)

## Goal
Two parallel tracks:
1. **Posture Signal Track (PC-P):** Close the engine posture writer gaps so `resource_security_posture` has a complete merged row per resource per scan.
2. **CSP Coverage Track (PC-CSP):** Close the check rule + topology + analysis gaps across all 7 CSPs (AWS, Azure, GCP, OCI, AliCloud, IBM, K8s).

---

## Actual CSP Coverage Baseline (2026-05-16)

### Check Rule Coverage by Engine Dimension

| Engine | AWS | Azure | GCP | OCI | AliCloud | IBM | K8s |
|--------|-----|-------|-----|-----|----------|-----|-----|
| Network | 454 | 199 | 96 | 324 | ~71 | 107 | **7** ← thin |
| IAM | 14 | 11 | 17 | 28 | ~8 | 42 | **5** ← thin |
| DataSec | 1169 | 81 | 43 | 154 | ~12 | 71 | 11 |
| Encryption | 1599 | 381 | 261 | 669 | ~18 | 52 | 81 |
| DBSec | 55 | 60 | 21 | 198 | ~5 | **0** ← gap | **0** ← gap |
| Container | 124 | 125 | 109 | 60 | ~6 | 48 | 802 |
| AI Security | **0** | **0** | **0** | **0** | **0** | **0** | **0** ← ALL gaps |

### Network Topology Depth per CSP

| CSP | L1 (Check Rules) | L2 (7-Layer Topology) | Status |
|-----|-----------------|----------------------|--------|
| AWS | ✅ | ✅ Full | Complete |
| Azure | ✅ | ✅ Full (VNet/NSG/AppGW/WAF/NetworkWatcher) | Complete |
| GCP | ✅ | ✅ Full (VPC/Firewall/Routes/CloudArmor/FlowLogs) | Complete |
| OCI | ✅ | ✅ Full (VCN/SecurityLists/NSG/WAAS/FlowLogs) | Complete |
| AliCloud | ✅ | ✅ Full (VPC/SecurityGroups/SLB/WAF/ActionTrail) | Complete |
| IBM | ✅ 107 rules | ❌ STUB — `IBMNetworkProvider` returns 0 findings | **→ PC-P2-03** |
| K8s | ✅ 7 rules | ❌ DEFERRED (conceptually different topology) | **→ PC-P2-03** |

### CDR Log Source Coverage

| CSP | Log Source | Reader Exists | Status |
|-----|-----------|---------------|--------|
| AWS | CloudTrail | ✅ | Full |
| Azure | Azure Activity Logs | ✅ | Full |
| GCP | GCP Cloud Audit Logs | ✅ | Full |
| OCI | OCI Audit | ✅ | Full |
| AliCloud | ActionTrail | ✅ | Full |
| IBM | IBM COS (Activity Tracker) | ✅ | Full |
| K8s | K8s Audit Logs | ✅ | Full |

### Discovery File Coverage

| CSP | YAML Files | Status |
|-----|-----------|--------|
| AWS | 512 | Comprehensive |
| Azure | 350 | Good |
| GCP | 355 | Good |
| OCI | 208 | Adequate |
| AliCloud | 213 | Adequate |
| IBM | 112 | Thin — some stubs |
| K8s | 89 | Adequate for K8s core resources |

### Posture Signal Writers (current state)

| Engine | Writer Exists? | Which CSPs Produce Output? |
|--------|---------------|---------------------------|
| IAM | ✅ | All CSPs (rule_id pattern matching, CSP-agnostic) |
| Network | ✅ | All CSPs (but IBM produces 0 due to stub topology) |
| DataSec | ✅ | All CSPs |
| CDR | ✅ | All CSPs |
| **Encryption** | ❌ No writer | — |
| **DBSec** | ❌ No writer | — |
| **Container** | ❌ No writer | — |
| **Vulnerability** | ❌ No writer | — |
| **AI Security** | ❌ No writer | — |

---

## Story Index

### Track 1 — Posture Signal Track (PC-P)

#### Phase 0 — Foundation
| Story | Title | Points | Tier |
|-------|-------|--------|------|
| [PC-P0-01](PC-P0-01-db-migration-new-posture-columns.md) | DB migration: container + vuln + AI + composite columns | 3 | A |

#### Phase 1 — Tier A: Ship This Sprint
| Story | Title | Points | What's missing |
|-------|-------|--------|----------------|
| [PC-P1-01](PC-P1-01-encryption-posture-writer.md) | Encryption posture writer | 3 | Writer only; 6 cols exist in table |
| [PC-P1-02](PC-P1-02-dbsec-posture-writer.md) | DBSec posture writer | 3 | Writer only; 3 cols exist in table |
| [PC-P1-03](PC-P1-03-container-security-posture-writer.md) | Container security posture writer | 3 | Writer + new cols (PC-P0-01) |
| [PC-P1-04](PC-P1-04-vulnerability-posture-writer.md) | Vulnerability posture writer | 3 | Writer + new cols (PC-P0-01) |
| [PC-P1-05](PC-P1-05-network-missing-signals.md) | Network: is_in_private_subnet + network_detail | 2 | 10-line fix in existing writer |
| [PC-P1-06](PC-P1-06-iam-reachable-pii-cross-engine.md) | IAM: reachable_pii_store_count cross-engine | 3 | Cross-engine join on posture table |
| [PC-P1-07](PC-P1-07-attack-path-composite-flags.md) | Attack-path: 5 composite danger flags | 3 | New composite_flags.py + risk boosts |

**Tier A total: 23 pts**

#### Phase 2 — Tier B: Next Sprint
| Story | Title | Points | External Input |
|-------|-------|--------|----------------|
| [PC-P2-01](PC-P2-01-kev-catalog-integration.md) | CISA KEV catalog → has_known_exploit | 5 | CISA public API (free) |
| [PC-P2-02](PC-P2-02-cdr-iam-cross-engine-actor-role.md) | CDR→IAM actor-role cross-link | 5 | Cross-engine DB join |
| [PC-P2-03](PC-P2-03-ibm-k8s-network-topology.md) | IBM Cloud + K8s network topology (the two actual stubs) | 8 | Discovery data already collected |
| [PC-P2-04](PC-P2-04-ai-security-posture-writer.md) | AI Security posture writer | 4 | CDR cross-reference |

**Tier B total: 22 pts**

#### Phase 3 — Tier C: Separate Sprints
| Story | Title | Points | Gate |
|-------|-------|--------|------|
| [PC-P3-01](PC-P3-01-container-runtime-security-design.md) | Container runtime: Falco/GuardDuty ADR + spike | 5 | Kernel compat check |
| [PC-P3-02](PC-P3-02-risk-monte-carlo-simulation.md) | Risk: Monte Carlo ranges ($450K–$7.2M) | 8 | numpy; UI/BFF changes |
| [PC-P3-03](PC-P3-03-cdr-ml-behavioral-anomaly.md) | CDR: Isolation Forest ML anomaly | 13 | 30+ days history |
| [PC-P3-04](PC-P3-04-datasec-native-dlp-all-csps.md) | DataSec: native DLP all 5 CSPs (Macie/Purview/GCP DLP/OCI DataSafe/AliCloud SDDP) | 13 | Per-CSP opt-in + cost approval |
| [PC-P3-05](PC-P3-05-secops-iac-scanning.md) | SecOps: IaC scanning (Terraform + CloudFormation via Checkov) | 8 | Git repo onboarding done |

**Tier C total: 47 pts**

---

### Track 2 — CSP Coverage Track (PC-CSP)

| Story | Title | Points | CSPs | Gap Closed |
|-------|-------|--------|------|------------|
| [PC-CSP-00](PC-CSP-00-coverage-matrix-methodology.md) | Coverage matrix script + baseline | 5 | All | Methodology + baseline JSON |
| [PC-CSP-01](PC-CSP-01-ai-security-rules-all-csps.md) | AI security check rules (0→5+ per CSP) | 8 | All 7 | AI security coverage from 0 |
| [PC-CSP-02](PC-CSP-02-ibm-dbsec-k8s-dbsec-rules.md) | IBM + K8s DBSec rules (0→8+ each) | 5 | IBM, K8s | DBSec coverage from 0 |
| [PC-CSP-03](PC-CSP-03-k8s-network-iam-rule-expansion.md) | K8s network (7→25) + IAM (5→18) rules | 5 | K8s | Network/IAM rule depth |

**CSP Track total: 23 pts**

---

### Track 3 — Provider Gap Closure (PC-GAP)

Closes Pattern A stubs and missing provider files. These stories implement `analyze()` logic for CSPs that currently return empty — highest ROI because the engine architecture already exists.

| Story | Title | Points | Engine | CSPs | Gap Type |
|-------|-------|--------|--------|------|----------|
| [PC-GAP-01](PC-GAP-01-iam-alicloud-ibm-analyze.md) | IAM: AliCloud + IBM analyze() | 6 | IAM | AliCloud, IBM | Pattern A stub → full |
| [PC-GAP-02](PC-GAP-02-datasec-ibm-analyze.md) | DataSec: IBM analyze() | 3 | DataSec | IBM | Pattern A partial → full |
| [PC-GAP-03](PC-GAP-03-ai-security-ibm-analyze.md) | AI Security: IBM analyze() | 3 | AI Security | IBM | Pattern A partial → full |
| [PC-GAP-04](PC-GAP-04-dbsec-ibm-provider.md) | DBSec: IBM provider (ibm.py) | 4 | DBSec | IBM | Missing file → full 5-pillar |
| [PC-GAP-05](PC-GAP-05-encryption-pattern-a-upgrade.md) | Encryption: AWS Pattern A (KMS+ACM+TLS) | 5 | Encryption | AWS | Pattern B → Pattern A |
| [PC-GAP-06](PC-GAP-06-container-k8s-pattern-a-upgrade.md) | Container: K8s Pattern A (secCtx+RBAC+NetPol) | 5 | Container | K8s | Pattern B → Pattern A |

**Provider Gap total: 26 pts**

**Implementation order:**
```
PC-GAP-01  PC-GAP-02  PC-GAP-03  PC-GAP-04  ← parallel (Pattern A stubs, independent)
    ↓
PC-GAP-05  PC-GAP-06  ← parallel (Pattern B→A upgrades; need PC-P1-01/PC-P1-03 writers first)
```

---


---

## Composite Danger Flags → Risk Engine Boosts

| Flag | Engines | Boost |
|------|---------|-------|
| `internet_exposed_with_pii` | network + datasec | +35 |
| `unencrypted_pii_store` | encryption + datasec | +20 |
| `admin_role_without_mfa` | iam | +25 |
| `exploitable_exposed_resource` | network + vuln + KEV | +40 |
| `cdr_active_on_unencrypted` | cdr + encryption | +45 |
| `active_cdr_actor_on_admin_role` | cdr + iam | +50 |

---

## Tier A Implementation Order

```
PC-P0-01 (migration 024)
    ↓
PC-P1-01  PC-P1-02  PC-P1-05  ← parallel (cols already in table)
PC-P1-03  PC-P1-04              ← parallel (need P0-01 first)
    ↓
PC-P1-06 (needs IAM + DataSec writers live)
    ↓
PC-P1-07 (needs all posture signals populated — run last)
```

**CSP Track runs in parallel with Posture Track** (different codebases):
```
PC-CSP-00 (baseline script, first)
    ↓
PC-CSP-01  PC-CSP-02  PC-CSP-03  ← parallel (all are rule catalog work)
```

---

### Track 4 — Analysis Depth (PC-DEPTH)

Closes depth gaps **within existing working providers** — detection modules for attack vectors the engine has config data for but doesn't yet analyze.

| Story | Title | Points | Engine | Data Sources | New Posture Columns |
|-------|-------|--------|--------|-------------|-------------------|
| [PC-DEPTH-01](PC-DEPTH-01-iam-privilege-escalation-paths.md) | IAM: Privilege escalation path detection (PassRole/CreatePolicy/AssumeRole chains) | 5 | IAM | discovery + CDR | `has_priv_escalation_path`, `priv_escalation_hop_count`, `priv_escalation_cdr_confirmed` |
| [PC-DEPTH-02](PC-DEPTH-02-network-azure-gcp-oci-7layer.md) | Network: Azure/GCP/OCI/AliCloud 7-layer topology refactor | 8 | Network | discovery only | `is_in_private_subnet` (populated for non-AWS, was null) |
| [PC-DEPTH-03](PC-DEPTH-03-encryption-azure-gcp-oci-pattern-a.md) | Encryption: Azure/GCP/OCI Pattern A (cert expiry + TLS + KMS rotation) | 4 | Encryption | discovery only | `cert_days_remaining`, `tls_version`, `has_kms_managed_key` (non-AWS) |
| [PC-DEPTH-04](PC-DEPTH-04-datasec-cross-account-s3-lakeformation.md) | DataSec: Cross-account S3 + Lake Formation bypass detection | 3 | DataSec | discovery + CDR | `has_exfil_path=true` (CDR confirmed), `can_access_pii` |
| [PC-DEPTH-05](PC-DEPTH-05-container-eks-ecr-depth.md) | Container: EKS node AMI age + ECR scan-on-push + AKS Azure AD RBAC | 3 | Container | discovery + CDR + vuln | `ecr_scan_on_push_enabled`, `eks_node_ami_outdated` |
| [PC-DEPTH-06](PC-DEPTH-06-cdr-exfil-sequence-detection.md) | CDR: Multi-event exfiltration sequence detection (recon→stage→exfil) | 5 | CDR | cdr_findings + cdr_actor_daily_stats | `has_exfil_path=true` (sequence confirmed cross-engine) |

**Analysis Depth total: 28 pts**

**Implementation order:**
```
PC-INFRA-01 (migration 027 — new posture columns first)
    ↓
PC-DEPTH-02  PC-DEPTH-03  PC-DEPTH-04  ← parallel (use cols already in 023)
PC-DEPTH-01  PC-DEPTH-05               ← parallel (use new cols from migration 027)
    ↓
PC-DEPTH-06  ← CDR sequence (last — uses baselines from prior CDR scans)
```

---

### Track 5 — Infrastructure (PC-INFRA)

Cross-cutting stories: DB migrations, security_findings wiring, and BFF endpoint updates needed to surface all depth analysis in the UI.

| Story | Title | Points | Blocks |
|-------|-------|--------|--------|
| [PC-INFRA-01](PC-INFRA-01-posture-depth-migration.md) | Migration 027: IAM escalation + ECR/EKS posture columns | 2 | PC-DEPTH-01, PC-DEPTH-05 |
| [PC-INFRA-02](PC-INFRA-02-depth-findings-security-findings-wire.md) | Wire PC-DEPTH new finding types to security_findings | 2 | After PC-DEPTH-01/04/05/06 |
| [PC-INFRA-03](PC-INFRA-03-bff-posture-depth-columns.md) | BFF: expose new posture columns + `category` findings filter | 3 | After PC-INFRA-01 |

**Infrastructure total: 7 pts**

**Implementation order:**
```
PC-INFRA-01 (migration — before any depth engine code)
    ↓
PC-DEPTH stories (write to new columns)
    ↓
PC-INFRA-02 (wire new findings to security_findings)
    ↓
PC-INFRA-03 (BFF: new columns + category filter visible in UI)
```

---

## Complete New Column List for resource_security_posture

### Migration 023 (already exists) — needs writers only
`is_encrypted_at_rest`, `is_encrypted_in_transit`, `has_kms_managed_key`, `has_valid_certificate`, `cert_days_remaining`, `tls_version` ← encryption engine  
`connected_db_count`, `db_auth_type`, `connected_db_uids` ← dbsec engine  
`is_in_private_subnet`, `network_detail` ← network engine (exists, not written)  
`reachable_pii_store_count` ← IAM/attack-path cross-engine

### Migration 024 (PC-P0-01) — new columns
**Container:** `has_privileged_container`, `image_has_critical_cve`, `k8s_rbac_overpermissive`, `container_network_policy_missing`, `container_security_score`  
**Vulnerability:** `vuln_critical_count`, `vuln_high_count`, `has_known_exploit`, `epss_max`  
**AI Security:** `has_shadow_ai_service`, `ai_model_publicly_accessible`, `ai_training_data_has_pii`  
**Composite (attack-path computed):** `unencrypted_pii_store`, `internet_exposed_with_pii`, `admin_role_without_mfa`, `exploitable_exposed_resource`, `cdr_active_on_unencrypted`

### Migration 027 (PC-INFRA-01) — depth analysis columns
**IAM escalation:** `has_priv_escalation_path`, `priv_escalation_hop_count`, `priv_escalation_cdr_confirmed`  
**Container ECR/EKS:** `ecr_scan_on_push_enabled`, `eks_node_ami_outdated`

### Migration 028+ (Tier B/C — separate future sprints)
`active_cdr_actor_on_admin_role` ← PC-P2-02  
`cdr_ml_anomaly_score` ← PC-P3-03  
`dlp_classified`, `dlp_sensitive_obj_count` ← PC-P3-04  
`iac_misconfiguration_count`, `iac_critical_count` ← PC-P3-05  
`container_escape_attempt`, `runtime_shell_detected` ← PC-P3-01
