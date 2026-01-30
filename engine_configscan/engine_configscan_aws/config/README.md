# Configuration Files

Clean, minimal configuration - only files actively used by the engine.

---

## 📁 Active Configuration Files

### 1. **`service_list.json`** ✅
**Used by:** `boto3_engine_simple.py`, `reporting_manager.py`, `exception_manager.py`

**Purpose:** Define AWS services and their properties

**Structure:**
```json
{
  "services": [
    {
      "name": "s3",
      "enabled": true,
      "scope": "global",
      "arn_pattern": "arn:aws:s3:::{resource_id}",
      "resource_types": ["bucket"]
    }
  ]
}
```

**Fields:**
- `name` - Service identifier (lowercase)
- `enabled` - Include in scans (true/false)
- `scope` - "global" or "regional"
- `arn_pattern` - ARN template for resources
- `resource_types` - List of resource types

---

### 2. **`check_exceptions.yaml`** ✅
**Used by:** `reporting_manager.py`, `exception_manager.py`

**Purpose:** Define compliance check exceptions

**Structure:**
```yaml
exceptions:
  - id: ex-chk-1
    rule_id: ec2_instance_imdsv2_enabled
    effect: mark_skipped
    selector:
      account: "123456789012"
      region: us-east-1
    reason: "Temporary exemption"
    expires_at: "2025-12-31T23:59:59Z"
```

**Fields:**
- `id` - Unique exception identifier
- `rule_id` - Compliance check to exempt
- `effect` - `mark_skipped`, `skip_check`, or `exempt_results`
- `selector` - Account/region/resource scope
- `reason` - Justification
- `expires_at` - Expiration date (ISO 8601) or `null`

---

### 3. **`actions.yaml`** ✅
**Used by:** `reporting_manager.py`, `action_runner.py`

**Purpose:** Define remediation actions

**Structure:**
```yaml
standard_actions:
  enable_versioning:
    description: "Enable S3 bucket versioning"
    service: "s3"
    operation: "put_bucket_versioning"
    params:
      VersioningConfiguration:
        Status: Enabled
```

---

### 4. **`actions_selection.yaml`** ✅
**Used by:** `reporting_manager.py`, `action_runner.py`

**Purpose:** Select which actions to enable per check

**Structure:**
```yaml
profiles:
  default:
    selected_actions_by_check:
      aws.s3.bucket_versioning_enabled:
        - enable_versioning

active_profile: default
```

---

## 🎯 Usage

### Enable/Disable Services

```bash
vim config/service_list.json
# Change "enabled": true/false
```

### Add Check Exception

```bash
vim config/check_exceptions.yaml
# Add to exceptions list
```

### Configure Actions

```bash
vim config/actions.yaml  # Define actions
vim config/actions_selection.yaml  # Enable actions
```

---

## 🧹 Cleaned Files

**Removed unused/experimental files:**
- ❌ `exceptions.yaml` (not integrated)
- ❌ `scanning_config.yaml` (not used)
- ❌ `multi_account_config.yaml` (redundant)
- ❌ Configuration documentation files

**Result:** Only 4 essential files that are actively used by the code.

---

## 📝 File Summary

| File | Size | Used By | Purpose |
|------|------|---------|---------|
| `service_list.json` | 31KB | Engine, Reporting | Service definitions |
| `check_exceptions.yaml` | 250B | Reporting, Exceptions | Compliance exemptions |
| `actions.yaml` | 498B | Actions, Reporting | Remediation actions |
| `actions_selection.yaml` | 363B | Actions, Reporting | Action profiles |

**Total:** 4 files, ~32KB

---

## ✅ Clean & Ready

Only essential configuration files remain - all actively used by the engine.
