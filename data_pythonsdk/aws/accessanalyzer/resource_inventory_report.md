# ACCESSANALYZER - Resource Inventory Report

**Generated:** 2026-01-20T19:24:28.756993

**Root Operations:** ListAnalyzers, ListPolicyGenerations

---

## Primary Resource

### analyzer

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `accessanalyzer.analyzer_arn`

#### ✅ Can be produced from ROOT operations:

- `ListAnalyzers`
- `ListAnalyzers`
- `ListPolicyGenerations`

---

### policy_generation_principal

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `accessanalyzer.policy_generation_principal_arn`

#### ✅ Can be produced from ROOT operations:

- `ListPolicyGenerations`

---

### resource

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `accessanalyzer.resource_resource_arn`

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetAnalyzedResource`
- `GetFindingRecommendation`
- `ListAnalyzedResources`

---

## Configuration

### archive_rule_rule

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** CONFIGURATION
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetArchiveRule`
- `ListArchiveRules`

---

## Ephemeral

### access_preview

- **Status:** ❌ Not in inventory 
- **Classification:** EPHEMERAL
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetAccessPreview`
- `GetFinding`
- `GetFindingV2`
- `ListAccessPreviewFindings`
- `ListAccessPreviews`
- `ListFindings`
- `ListFindingsV2`

---

### access_preview_analyzer

- **Status:** ❌ Not in inventory 
- **Classification:** EPHEMERAL
- **Has ARN:** Yes
- **ARN Entity:** `accessanalyzer.access_preview_analyzer_arn`

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetAccessPreview`
- `ListAccessPreviews`

---

### finding_existing_finding

- **Status:** ❌ Not in inventory 
- **Classification:** EPHEMERAL
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `ListAccessPreviewFindings`

---

### policy_generation_job

- **Status:** ❌ Not in inventory 
- **Classification:** EPHEMERAL
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `ListPolicyGenerations`

---
