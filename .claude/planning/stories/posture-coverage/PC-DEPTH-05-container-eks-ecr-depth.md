# Story PC-DEPTH-05: Container Engine — EKS/ECR/AKS Analysis Depth

## Status: done

## Metadata
- **Phase**: Analysis Depth Track
- **Sprint**: Posture Coverage Enhancement
- **Points**: 3
- **Priority**: P2 — ECR + EKS gaps are the two most common container misconfigs missed by current pattern B analysis
- **Depends on**: PC-GAP-06 (Container pattern A base class done)
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-reviewer

## Gap Being Closed

PC-GAP-06 upgrades the Container engine to Pattern A. After that story, the AWS `AWSContainerProvider.analyze()` covers pod security context, RBAC chains, and NetworkPolicy coverage. What it does NOT cover:

1. **EKS node group AMI age** — Each EKS managed node group has a `releaseVersion` (e.g. `1.29.3-20240412`). If the node AMI is > 60 days old, it may miss OS-level CVE patches applied in newer AMI releases. Current check rules evaluate Kubernetes workload config, not the node AMI lifecycle.

2. **ECR scan-on-push** — AWS ECR repositories have `imageScanningConfiguration.scanOnPush: true/false`. When `false`, images are never scanned for CVEs unless the user triggers a manual scan. Current container engine doesn't read ECR configuration at all.

3. **ECR cross-account pull policy** — ECR repositories can have resource-based policies allowing external AWS accounts to pull images. A compromised supply chain account pulling malicious images into production is a real vector. Current engine reads pod image URIs but not the ECR repository policy.

4. **AKS Azure AD RBAC integration** — AKS clusters can be Azure AD-integrated (`aadProfile.managed = true`) with Azure RBAC for K8s (`enableAzureRBAC = true`). Without this, K8s RBAC is the only control. Current Azure container provider doesn't check AKS AAD integration.

---

## Data Required

### Source 1 — Discovery Engine (`discovery_findings`)

**For EKS node group AMI age:**

| Discovery ID | What it provides | Field used |
|-------------|-----------------|-----------|
| `aws.eks.describe_node_group` | Node group config + release version | `raw_response.NodeGroup.ReleaseVersion` (format: `k8s_ver-YYYYMMDD`) |
| `aws.eks.list_node_groups` | All node groups per cluster | `raw_response.NodeGroups[]` |

**For ECR scan-on-push and pull policies:**

| Discovery ID | What it provides | Field used |
|-------------|-----------------|-----------|
| `aws.ecr.describe_repositories` | Repository config | `raw_response.repositories[].imageScanningConfiguration.scanOnPush` |
| `aws.ecr.get_repository_policy` | Repository resource policy | `raw_response.policyText` (JSON string) |

**For AKS Azure AD RBAC:**

| Discovery ID | What it provides | Field used |
|-------------|-----------------|-----------|
| `azure.aks.list_managed_clusters` | AKS cluster properties | `properties.aadProfile.managed`, `properties.aadProfile.enableAzureRBAC`, `properties.disableLocalAccounts` |

### Source 2 — CDR Engine (`cdr_findings`) — ECR cross-account enrichment

```sql
SELECT actor_principal, operation, resource_uid, COUNT(*) AS pull_count
FROM cdr_findings
WHERE tenant_id = %s
  AND service = 'ecr'
  AND operation IN ('GetDownloadUrlForLayer', 'BatchGetImage', 'InitiateLayerUpload')
  AND actor_principal NOT LIKE '%:' || %s || ':%%'  -- exclude same-account principals
  AND event_time > NOW() - INTERVAL '30 days'
GROUP BY actor_principal, operation, resource_uid
```

Cross-account ECR pulls that have been **actively exercised** upgrade the cross-account policy finding to CRITICAL (supply chain risk confirmed).

### Source 3 — Vulnerability Engine — cross-reference only

When ECR `scanOnPush=false` is detected and the vulnerability engine has CVE findings for images hosted in that repository (`sbom_components.resource_uid LIKE '%:repository/%'`), the finding severity is upgraded to CRITICAL (known CVEs + no scanning = confirmed blind spot).

```sql
SELECT DISTINCT sc.resource_uid, COUNT(st.cve_id) AS cve_count,
       MAX(st.epss_score) AS max_epss
FROM sbom_components sc
JOIN sbom_threat_intel st USING (cve_id)
WHERE sc.tenant_id = %s
  AND sc.resource_uid LIKE '%ecr%:%repository/%'
  AND st.epss_score > 0.1
GROUP BY sc.resource_uid
```

---

## Detection Logic

### Module: `_analyze_eks_node_ami_age()`

```python
def _analyze_eks_node_ami_age(self, disc_data, scan_run_id, tenant_id, account_id, now):
    findings = []
    node_groups = disc_data.get("aws.eks.describe_node_group", [])
    for ng in node_groups:
        release = ng.get("NodeGroup", {}).get("ReleaseVersion", "")
        # format: "1.29.3-20240412" — extract date suffix
        if not release:
            continue
        parts = release.split("-")
        if len(parts) < 2:
            continue
        try:
            ami_date = datetime.strptime(parts[-1], "%Y%m%d").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        age_days = (now - ami_date).days
        if age_days > 90:
            severity = "critical"
        elif age_days > 60:
            severity = "high"
        else:
            continue   # < 60 days = acceptable

        findings.append({
            "rule_id": "aws.eks.node_group.ami_up_to_date",
            "severity": severity,
            "finding_data": {
                "node_group_name": ng.get("NodeGroup", {}).get("NodegroupName"),
                "release_version": release,
                "ami_age_days": age_days,
            },
            ...
        })
    return findings
```

**Severity:**
| AMI age | Severity |
|---------|---------|
| > 90 days | CRITICAL |
| 61–90 days | HIGH |
| ≤ 60 days | PASS (skip) |

### Module: `_analyze_ecr_scan_config()`

```python
def _analyze_ecr_scan_config(self, disc_data, scan_run_id, tenant_id, account_id):
    findings = []
    repos = disc_data.get("aws.ecr.describe_repositories", [])
    for repo in repos:
        scan_on_push = repo.get("imageScanningConfiguration", {}).get("scanOnPush", False)
        if not scan_on_push:
            findings.append({
                "rule_id": "aws.ecr.repository.scan_on_push_enabled",
                "severity": "high",
                "finding_data": {"repository_name": repo.get("repositoryName")},
                ...
            })

        # Cross-account pull policy check
        policy_text = repo.get("_policy_text")   # pre-parsed from get_repository_policy
        if policy_text:
            for stmt in policy_text.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue
                arns = _flatten_principal(stmt.get("Principal", {}))
                for arn in arns:
                    if not _is_same_account(arn, account_id):
                        findings.append({
                            "rule_id": "aws.ecr.repository.no_cross_account_pull",
                            "severity": "high",
                            ...
                        })
    return findings
```

### Module: `_analyze_aks_aad_rbac()` — Azure provider

```python
def _analyze_aks_aad_rbac(self, disc_data, scan_run_id, tenant_id, account_id):
    findings = []
    clusters = disc_data.get("azure.aks.list_managed_clusters", [])
    for cluster in clusters:
        props = cluster.get("properties", {})
        aad = props.get("aadProfile", {})
        if not aad.get("managed", False):
            # Not Azure AD-integrated at all
            findings.append({
                "rule_id": "azure.aks.cluster.azure_ad_integration_enabled",
                "severity": "high",
                ...
            })
        elif not aad.get("enableAzureRBAC", False):
            # AAD integrated but Azure RBAC not enabled — K8s RBAC only
            findings.append({
                "rule_id": "azure.aks.cluster.azure_rbac_enabled",
                "severity": "medium",
                ...
            })
        if not props.get("disableLocalAccounts", False):
            # Local accounts still enabled — admin kubeconfig can bypass AAD
            findings.append({
                "rule_id": "azure.aks.cluster.local_accounts_disabled",
                "severity": "high",
                ...
            })
    return findings
```

---

## Findings Produced

| Rule ID | Severity | Engine | Notes |
|---------|---------|--------|-------|
| `aws.eks.node_group.ami_up_to_date` | CRITICAL/HIGH | Container | Node AMI > 60 days old |
| `aws.ecr.repository.scan_on_push_enabled` | HIGH | Container | ECR repo missing scan-on-push |
| `aws.ecr.repository.no_cross_account_pull` | HIGH | Container | External account can pull from ECR |
| `aws.ecr.repository.no_cross_account_pull` | CRITICAL | Container | Same + CDR confirms pull from external account |
| `azure.aks.cluster.azure_ad_integration_enabled` | HIGH | Container | AKS not AAD-integrated |
| `azure.aks.cluster.azure_rbac_enabled` | MEDIUM | Container | AAD integrated but Azure RBAC off |
| `azure.aks.cluster.local_accounts_disabled` | HIGH | Container | Local kubeconfig accounts still enabled |

---

## Posture Signals Written

Updated in `write_container_posture_signals()` — two new posture columns (see PC-INFRA-01 migration):
- `ecr_scan_on_push_enabled = False` when any ECR repo is missing scan-on-push
- `eks_node_ami_outdated = True` when any node group AMI is > 60 days old

---

## CDR Enrichment

Cross-account ECR pull confirmed by CDR → upgrade `aws.ecr.repository.no_cross_account_pull` severity to CRITICAL:

```python
active_repos = {row["resource_uid"] for row in cdr_cross_account_ecr_pulls}
for finding in findings:
    if finding["rule_id"] == "aws.ecr.repository.no_cross_account_pull":
        if finding["resource_uid"] in active_repos:
            finding["severity"] = "critical"
            finding["finding_data"]["cdr_confirmed"] = True
```

---

## Acceptance Criteria

- [ ] AC-1: `aws.eks.node_group.ami_up_to_date` fires for node groups with `releaseVersion` date older than 60 days; does NOT fire for node groups with AMI < 60 days old
- [ ] AC-2: `aws.ecr.repository.scan_on_push_enabled` fires for ECR repos with `imageScanningConfiguration.scanOnPush=false`; PASS for `scanOnPush=true`
- [ ] AC-3: `aws.ecr.repository.no_cross_account_pull` fires for ECR repos with cross-account Principal in Allow statement; same-account principals NOT flagged
- [ ] AC-4: CDR enrichment: finding severity upgrades to CRITICAL when CDR has `BatchGetImage` from external account on the same repo in last 30 days
- [ ] AC-5: `azure.aks.cluster.azure_ad_integration_enabled` fires for AKS clusters with `aadProfile.managed=false` or missing `aadProfile`
- [ ] AC-6: `ecr_scan_on_push_enabled=false` and `eks_node_ami_outdated=true` written to `resource_security_posture` for affected resources
- [ ] AC-7: All DB queries (discovery + CDR + vuln) include `AND tenant_id = %s`

## MITRE ATT&CK
| Technique | Addressed by |
|-----------|-------------|
| T1525 | Implant Internal Image — ECR cross-account pull (supply chain) |
| T1609 | Container Administration Command — privileged container via outdated AMI |
| T1611 | Escape to Host — CVEs in outdated node AMI enabling container escape |

## Definition of Done
- [ ] `_analyze_eks_node_ami_age()` and `_analyze_ecr_scan_config()` added to `AWSContainerProvider`
- [ ] `_analyze_aks_aad_rbac()` added to `AzureContainerProvider`
- [ ] CDR enrichment wired for ECR cross-account pull confirmation
- [ ] Unit tests in `tests/unit/container/test_eks_ecr_depth.py`
- [ ] Container engine rebuilt and deployed
- [ ] After AWS scan: `SELECT rule_id, COUNT(*) FROM container_sec_findings WHERE rule_id LIKE '%ecr%' OR rule_id LIKE '%node_group%' GROUP BY rule_id` shows new rules