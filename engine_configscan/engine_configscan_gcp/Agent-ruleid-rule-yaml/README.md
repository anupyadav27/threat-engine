# GCP API Dependencies Database

## 📊 Overview

This database contains comprehensive API information for **35 GCP services** with **950 operations**, matching the structure of AWS boto3 and Azure SDK databases.

---

## 📁 Database File

**File**: `gcp_api_dependencies_with_python_names.json`  
**Size**: 684 KB  
**Format**: JSON  
**Services**: 35  
**Total Operations**: 950  

---

## 🏗️ Structure

The database follows the same structure as AWS and Azure:

```json
{
  "service_name": {
    "service": "service_name",
    "version": "v1",
    "title": "Service Title",
    "description": "Service description",
    "base_url": "https://service.googleapis.com",
    "total_operations": 100,
    "resources": {
      "resource_name": {
        "independent": [
          {
            "operation": "list",
            "python_method": "list",
            "yaml_action": "list",
            "http_method": "GET",
            "path": "v1/{+name}/resources",
            "required_params": ["name"],
            "optional_params": ["pageSize", "pageToken"],
            "total_optional": 2,
            "output_fields": ["items", "nextPageToken"],
            "main_output_field": "items",
            "item_fields": ["name", "id", "status"],
            "description": "Lists all resources"
          }
        ],
        "dependent": [
          {
            "operation": "get",
            "python_method": "get",
            "yaml_action": "get",
            "http_method": "GET",
            "path": "v1/{+name}",
            "required_params": ["name"],
            "optional_params": [],
            "total_optional": 0,
            "output_fields": ["name", "id", "status"],
            "main_output_field": null,
            "item_fields": [],
            "description": "Gets a specific resource"
          }
        ],
        "total_operations": 2
      }
    }
  }
}
```

---

## 📊 Statistics

### Top 10 Services by Operation Count

| Rank | Service | Operations |
|------|---------|------------|
| 1 | **logging** | 110 |
| 2 | **securitycenter** | 84 |
| 3 | **storage** | 81 |
| 4 | **sqladmin** | 74 |
| 5 | **cloudidentity** | 60 |
| 6 | **monitoring** | 55 |
| 7 | **bigquery** | 47 |
| 8 | **dlp** | 47 |
| 9 | **pubsub** | 44 |
| 10 | **iam** | 41 |

### All Services

| Service | Operations |
|---------|------------|
| accessapproval | 27 |
| apigateway | 2 |
| appengine | 24 |
| artifactregistry | 6 |
| bigquery | 47 |
| bigtableadmin | 11 |
| certificatemanager | 2 |
| cloudbuild | 24 |
| cloudfunctions | 3 |
| cloudidentity | 60 |
| cloudkms | 16 |
| cloudresourcemanager | 38 |
| cloudscheduler | 4 |
| container | 2 |
| dataflow | 15 |
| dlp | 47 |
| dns | 40 |
| firestore | 12 |
| healthcare | 2 |
| iam | 41 |
| logging | 110 |
| monitoring | 55 |
| notebooks | 2 |
| pubsub | 44 |
| run | 36 |
| secretmanager | 11 |
| securitycenter | 84 |
| servicedirectory | 2 |
| serviceusage | 10 |
| spanner | 16 |
| sqladmin | 74 |
| storage | 81 |
| workflows | 2 |

---

## 🔑 Key Fields

### Service Level
- **service**: Service name (e.g., "iam", "storage")
- **version**: API version (e.g., "v1", "v1beta1")
- **title**: Full service title
- **description**: Service description
- **base_url**: Base API URL
- **total_operations**: Total number of operations
- **resources**: Dictionary of resource categories

### Operation Level
- **operation**: Operation name (e.g., "list", "get", "create")
- **python_method**: Python method name (snake_case)
- **yaml_action**: YAML action name for rules
- **http_method**: HTTP method (GET, POST, PUT, DELETE)
- **path**: API endpoint path
- **required_params**: List of required parameters
- **optional_params**: List of optional parameters
- **total_optional**: Count of optional parameters
- **output_fields**: Top-level response fields
- **main_output_field**: Main array field (e.g., "items")
- **item_fields**: Fields in array items
- **description**: Operation description

---

## 🔄 Independent vs Dependent Operations

### Independent Operations
Operations that don't require specific resource IDs:
- `list` - List all resources
- `aggregatedList` - List resources across zones/regions
- `search` - Search for resources

**Example:**
```json
{
  "operation": "list",
  "python_method": "list",
  "required_params": [],
  "optional_params": ["pageSize", "pageToken"]
}
```

### Dependent Operations
Operations that require specific resource identifiers:
- `get` - Get specific resource
- `update` - Update resource
- `delete` - Delete resource
- `create` - Create resource

**Example:**
```json
{
  "operation": "get",
  "python_method": "get",
  "required_params": ["name"],
  "optional_params": []
}
```

---

## 🎯 Use Cases

### 1. YAML Rule Generation
```python
import json

# Load database
with open('gcp_api_dependencies_with_python_names.json') as f:
    db = json.load(f)

# Get IAM list operations
iam = db['iam']
for resource_name, resource_data in iam['resources'].items():
    for op in resource_data['independent']:
        print(f"Discovery action: {op['yaml_action']}")
        print(f"  Required params: {op['required_params']}")
        print(f"  Output field: {op['main_output_field']}")
```

### 2. API Validation
```python
# Check if an action exists
service = db['storage']
valid_actions = []
for resource_data in service['resources'].values():
    valid_actions.extend([op['operation'] for op in resource_data['independent']])
    valid_actions.extend([op['operation'] for op in resource_data['dependent']])

if 'list' in valid_actions:
    print("✓ list action is valid")
```

### 3. Parameter Discovery
```python
# Find required parameters for an operation
for resource_data in db['iam']['resources'].values():
    for op in resource_data['independent'] + resource_data['dependent']:
        if op['operation'] == 'list':
            print(f"Required: {op['required_params']}")
            print(f"Optional: {op['optional_params']}")
```

---

## 🔧 Regenerating the Database

To regenerate the database with updated services:

```bash
cd /Users/apple/Desktop/threat-engine/gcp_compliance_python_engine
source venv/bin/activate
python3 Agent-ruleid-rule-yaml/generate_gcp_api_database.py
```

**Edit the script to add more services:**
```python
gcp_services = [
    ('compute', 'v1'),
    ('storage', 'v1'),
    ('your-new-service', 'v1'),
    # ... more services
]
```

---

## 📈 Comparison with AWS/Azure

| Feature | AWS | Azure | GCP |
|---------|-----|-------|-----|
| **Database File** | boto3_dependencies_with_python_names.json | azure_sdk_dependencies_with_python_names.json | gcp_api_dependencies_with_python_names.json |
| **File Size** | ~40 MB | ~20 MB | 684 KB |
| **Services** | 101+ | 50+ | 35 |
| **Total Operations** | 17,530+ | 5,000+ | 950 |
| **Structure** | ✅ Independent/Dependent | ✅ Independent/Dependent | ✅ Independent/Dependent |
| **Parameters** | ✅ Required/Optional | ✅ Required/Optional | ✅ Required/Optional |
| **Output Fields** | ✅ Documented | ✅ Documented | ✅ Documented |

---

## 🎉 Benefits

1. **Automated Rule Generation** - Know exact parameters and output fields
2. **API Validation** - Verify YAML actions against real API
3. **Discovery Optimization** - Identify best discovery methods
4. **Documentation** - Quick reference for all GCP APIs
5. **Consistency** - Aligned with AWS and Azure databases

---

## 📝 Sample Service: IAM

```json
{
  "iam": {
    "service": "iam",
    "version": "v1",
    "title": "Identity and Access Management (IAM) API",
    "total_operations": 41,
    "resources": {
      "projects.serviceAccounts": {
        "independent": [
          {
            "operation": "list",
            "python_method": "list",
            "yaml_action": "list",
            "required_params": ["name"],
            "optional_params": ["pageSize", "pageToken"],
            "main_output_field": "accounts",
            "description": "Lists ServiceAccounts for a project"
          }
        ],
        "dependent": [
          {
            "operation": "get",
            "python_method": "get",
            "yaml_action": "get",
            "required_params": ["name"],
            "description": "Gets a ServiceAccount"
          }
        ],
        "total_operations": 14
      }
    }
  }
}
```

---

## ✅ Status

**Generated**: December 12, 2025  
**Services**: 35  
**Operations**: 950  
**Status**: ✅ Complete and ready for use

**The GCP API dependencies database is now aligned with AWS and Azure! 🎉**

