# GCP Compliance Engine - Output Structure

## ✅ **ALIGNED WITH AWS & AZURE**

The GCP compliance engine now creates **project-based output folders** matching the AWS (account-based) and Azure (subscription-based) patterns.

---

## 📁 Output Structure

### **GCP Output** (Project-Based)
```
output/
├── latest -> scan_20251212_172721
└── scan_20251212_172721/
    ├── index.json                           # Index of all project folders
    ├── summary.json                         # Overall scan summary
    ├── logs/
    │   ├── scan.log                        # Scan execution log
    │   └── errors.log                      # Error log
    └── project_test-215908/                # Per-project folder
        ├── global_iam_checks.json          # IAM compliance checks
        ├── global_iam_inventory.json       # IAM resource inventory
        ├── global_pubsub_checks.json       # PubSub compliance checks
        └── global_pubsub_inventory.json    # PubSub resource inventory
```

### **Azure Output** (Subscription-Based) - For Comparison
```
output/
├── latest -> scan_20251212_170740
└── scan_20251212_170740/
    ├── summary.json
    └── subscription_f6d24b5d-51ed-47b7-9f6a-0ad194156b5e/
        ├── eastus_keyvault_checks.json
        └── eastus_keyvault_inventory.json
```

### **Pattern Alignment**

| CSP | Folder Pattern | Service Files |
|-----|----------------|---------------|
| **AWS** | `account_{account_id}/` | `{region}_{service}_checks.json` |
| **Azure** | `subscription_{subscription_id}/` | `{location}_{service}_checks.json` |
| **GCP** | `project_{project_id}/` | `{region}_{service}_checks.json` |

---

## 📊 File Contents

### **1. index.json** - Scan Index
```json
{
    "metadata": {
        "generated_at": "2025-12-12T17:28:11.351194Z",
        "scan_folder": "/path/to/scan"
    },
    "project_folders": [
        "project_test-215908"
    ],
    "summary": {
        "total_checks": 109,
        "passed": 0,
        "failed": 109,
        "skipped": 0,
        "errors": 0,
        "total_resources": 6,
        "compliance_rate": 0.0
    }
}
```

### **2. summary.json** - Overall Summary
```json
{
    "metadata": {
        "generated_at": "2025-12-12T17:28:11.350649Z",
        "scan_folder": "/path/to/scan",
        "total_projects": 1,
        "total_services": 2,
        "total_regions": 1
    },
    "summary": {
        "total_checks": 109,
        "passed": 0,
        "failed": 109,
        "skipped": 0,
        "errors": 0,
        "total_resources": 6,
        "compliance_rate": 0.0
    },
    "projects": ["test-215908"],
    "services": ["iam", "pubsub"],
    "regions": ["global"]
}
```

### **3. project_{id}/{region}_{service}_checks.json** - Service Checks
```json
{
    "service": "iam",
    "project": "test-215908",
    "region": "global",
    "summary": {
        "total": 82,
        "passed": 0,
        "failed": 82,
        "skipped": 0,
        "errors": 0
    },
    "timestamp": "2025-12-12T17:28:11.344951Z",
    "checks": [
        {
            "check_id": "gcp.iam.key.90_days",
            "title": "Ensure IAM Keys Are Rotated Every 90 Days",
            "severity": "high",
            "result": "FAIL",
            "project": "test-215908",
            "region": "global",
            "resource_id": "unknown"
        }
        // ... more checks
    ]
}
```

### **4. project_{id}/{region}_{service}_inventory.json** - Resource Inventory
```json
{
    "service": "iam",
    "project": "test-215908",
    "region": "global",
    "discovered": {
        "list_service_accounts": [],
        "list_roles": [],
        "list_service_account_keys": [],
        "list_workload_identity_pools": []
    },
    "count": 0,
    "timestamp": "2025-12-12T17:28:11.345072Z"
}
```

---

## 🔄 Multi-Project Example

When scanning multiple projects, the structure expands:

```
output/scan_20251212_172721/
├── index.json
├── summary.json
├── logs/
│   ├── scan.log
│   └── errors.log
├── project_prod-001/
│   ├── global_iam_checks.json
│   ├── global_iam_inventory.json
│   ├── us-central1_compute_checks.json
│   └── us-central1_compute_inventory.json
├── project_prod-002/
│   ├── global_iam_checks.json
│   ├── global_storage_checks.json
│   └── us-east1_compute_checks.json
└── project_dev-001/
    ├── global_iam_checks.json
    └── global_pubsub_checks.json
```

---

## 📈 Scan Results - Live Example

### **Latest Scan: scan_20251212_172721**

**Scanned**:
- **Projects**: 1 (test-215908)
- **Services**: 2 (iam, pubsub)
- **Regions**: 1 (global)

**Results**:
- **Total Checks**: 109
- **Passed**: 0
- **Failed**: 109
- **Skipped**: 0
- **Errors**: 0
- **Resources Discovered**: 6
- **Compliance Rate**: 0.0%

**Files Generated**:
```
output/latest/
├── index.json                          (410 bytes)
├── summary.json                        (547 bytes)
├── logs/
│   ├── scan.log
│   └── errors.log
└── project_test-215908/
    ├── global_iam_checks.json         (23 KB, 82 checks)
    ├── global_iam_inventory.json      (342 bytes)
    ├── global_pubsub_checks.json      (8.4 KB, 27 checks)
    └── global_pubsub_inventory.json   (252 bytes)
```

---

## ✨ Key Features

1. **Per-Project Organization** - Each project gets its own folder
2. **Service-Level Files** - Separate checks/inventory per service
3. **Regional Separation** - Regional services have region-prefixed files
4. **Global Services** - Global services use `global_` prefix
5. **Latest Symlink** - Quick access to most recent scan
6. **Comprehensive Metadata** - Timestamps, counts, summaries
7. **Compliance Metrics** - Pass/fail/skip/error tracking
8. **Resource Inventory** - Discovery results per service

---

## 🎯 Alignment Summary

| Feature | AWS | Azure | GCP |
|---------|-----|-------|-----|
| Per-Account/Project Folders | ✅ | ✅ | ✅ |
| Service-Level Files | ✅ | ✅ | ✅ |
| Inventory + Checks Separation | ✅ | ✅ | ✅ |
| Summary JSON | ✅ | ✅ | ✅ |
| Index File | ✅ | ✅ | ✅ |
| Latest Symlink | ✅ | ✅ | ✅ |
| Compliance Metrics | ✅ | ✅ | ✅ |
| Logs Directory | ✅ | ✅ | ✅ |

---

## 🚀 Usage

The output structure is automatically created when running scans:

```bash
# Single project
python3 -m engine.main_scanner --project my-project

# Multiple services
python3 -m engine.main_scanner --include-services "iam,pubsub,storage"

# Multiple projects
python3 -m engine.main_scanner --include-projects "proj1,proj2,proj3"
```

**All outputs are saved to**: `output/scan_YYYYMMDD_HHMMSS/`  
**Quick access via**: `output/latest/`

---

## ✅ Verification

To verify the output structure:

```bash
# List all project folders
ls -l output/latest/project_*/

# View summary
cat output/latest/summary.json | python3 -m json.tool

# View checks for a specific project and service
cat output/latest/project_test-215908/global_iam_checks.json | python3 -m json.tool
```

---

**The GCP engine now produces uniform, project-based output aligned with AWS and Azure! 🎉**

