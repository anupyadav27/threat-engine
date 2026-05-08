# ACCESSANALYZER - Minimal Operations List

**Generated:** 2026-01-20T19:31:00.890297

**Total Fields:** 67
**Total Operations Needed:** 14
**Independent Operations:** 2
**Dependent Operations:** 12
**Coverage:** 24.6%

---

## ✅ Independent Operations (Root Operations)

These operations can be called without any dependencies:

### 1. ListAnalyzers

- **Type:** Independent (Root)
- **Entities Covered:** 10
- **Covers:** accessanalyzer.analyzer_arn, accessanalyzer.analyzer_configuration, accessanalyzer.analyzer_created_at, accessanalyzer.analyzer_last_resource_analyzed, accessanalyzer.analyzer_last_resource_analyzed_at...

### 2. ListPolicyGenerations

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** accessanalyzer.policy_generation_completed_on, accessanalyzer.policy_generation_job_id, accessanalyzer.policy_generation_principal_arn, accessanalyzer.policy_generation_started_on

## ⚠️  Dependent Operations

These operations require inputs from other operations:

### 1. ListFindings

- **Type:** Dependent
- **Entities Covered:** 13
- **Covers:** accessanalyzer.access_preview_id, accessanalyzer.finding_action, accessanalyzer.finding_condition, accessanalyzer.finding_principal, accessanalyzer.finding_resource...
- **Requires:** accessanalyzer.analyzer_arn
- **Dependencies:** accessanalyzer.analyzer_arn

### 2. GetFindingV2

- **Type:** Dependent
- **Entities Covered:** 8
- **Covers:** accessanalyzer.analyzed_at, accessanalyzer.finding_detail_external_access_details, accessanalyzer.finding_detail_internal_access_details, accessanalyzer.finding_detail_unused_iam_role_details, accessanalyzer.finding_detail_unused_iam_user_access_key_details...
- **Requires:** accessanalyzer.access_preview_id, accessanalyzer.analyzer_arn
- **Dependencies:** accessanalyzer.access_preview_id, accessanalyzer.analyzer_arn

### 3. ListAccessPreviewFindings

- **Type:** Dependent
- **Entities Covered:** 3
- **Covers:** accessanalyzer.finding_change_type, accessanalyzer.finding_existing_finding_id, accessanalyzer.finding_existing_finding_status
- **Requires:** accessanalyzer.access_preview_id, accessanalyzer.analyzer_arn
- **Dependencies:** accessanalyzer.access_preview_id, accessanalyzer.analyzer_arn

### 4. GetAccessPreview

- **Type:** Dependent
- **Entities Covered:** 3
- **Covers:** accessanalyzer.access_preview, accessanalyzer.access_preview_analyzer_arn, accessanalyzer.access_preview_configurations
- **Requires:** accessanalyzer.access_preview_id, accessanalyzer.analyzer_arn
- **Dependencies:** accessanalyzer.access_preview_id, accessanalyzer.analyzer_arn

### 5. GetFindingRecommendation

- **Type:** Dependent
- **Entities Covered:** 3
- **Covers:** accessanalyzer.completed_at, accessanalyzer.recommended_step_unused_permissions_recommended_step, accessanalyzer.resource_resource_arn
- **Requires:** accessanalyzer.access_preview_id, accessanalyzer.analyzer_arn
- **Dependencies:** accessanalyzer.access_preview_id, accessanalyzer.analyzer_arn

### 6. GetFindingsStatistics

- **Type:** Dependent
- **Entities Covered:** 3
- **Covers:** accessanalyzer.findings_statistic_external_access_findings_statistics, accessanalyzer.findings_statistic_internal_access_findings_statistics, accessanalyzer.findings_statistic_unused_access_findings_statistics
- **Requires:** accessanalyzer.analyzer_arn
- **Dependencies:** accessanalyzer.analyzer_arn

### 7. GetAnalyzedResource

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** accessanalyzer.resource_actions, accessanalyzer.resource_shared_via
- **Requires:** accessanalyzer.analyzer_arn, accessanalyzer.resource_resource_arn
- **Dependencies:** accessanalyzer.analyzer_arn, accessanalyzer.resource_resource_arn

### 8. GetGeneratedPolicy

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** accessanalyzer.generated_policy_result, accessanalyzer.job_detail_job_error
- **Requires:** accessanalyzer.policy_generation_job_id
- **Dependencies:** accessanalyzer.policy_generation_job_id

### 9. ListArchiveRules

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** accessanalyzer.archive_rule_filter, accessanalyzer.archive_rule_rule_name
- **Requires:** accessanalyzer.analyzer_name
- **Dependencies:** accessanalyzer.analyzer_name

### 10. GetFinding

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** accessanalyzer.finding
- **Requires:** accessanalyzer.access_preview_id, accessanalyzer.analyzer_arn
- **Dependencies:** accessanalyzer.access_preview_id, accessanalyzer.analyzer_arn

### 11. GetAnalyzer

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** accessanalyzer.analyzer
- **Requires:** accessanalyzer.analyzer_name
- **Dependencies:** accessanalyzer.analyzer_name

### 12. GetArchiveRule

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** accessanalyzer.archive_rule
- **Requires:** accessanalyzer.analyzer_name, accessanalyzer.archive_rule_rule_name
- **Dependencies:** accessanalyzer.analyzer_name, accessanalyzer.archive_rule_rule_name

---

## 📋 Complete Operations List (In Order)

### Independent Operations:
1. `ListAnalyzers`
1. `ListPolicyGenerations`

### Dependent Operations:
1. `ListFindings`
1. `GetFindingV2`
1. `ListAccessPreviewFindings`
1. `GetAccessPreview`
1. `GetFindingRecommendation`
1. `GetFindingsStatistics`
1. `GetAnalyzedResource`
1. `GetGeneratedPolicy`
1. `ListArchiveRules`
1. `GetFinding`
1. `GetAnalyzer`
1. `GetArchiveRule`
