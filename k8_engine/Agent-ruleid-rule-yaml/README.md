# Kubernetes API Catalog - Agent Files

This directory contains the Kubernetes API catalog and related tools for compliance rule generation.

---

## 📁 **Production Files**

### **✅ USE THIS - SDK-Based Catalog**
```
k8s_api_catalog_from_sdk.json (884 KB)
```
**Complete K8s API catalog extracted from Kubernetes Python SDK:**
- 17 resources (Pod, Service, Deployment, etc.)
- 1,088 fields with full metadata
- 134 high-security fields identified
- 100% SDK-accurate field names and types

### **Backup Catalog**
```
k8s_api_catalog_enhanced.json (48 KB)
```
**Manual catalog (initial version)**
- 10 core resources
- Basic field definitions
- Use SDK-based version above instead

---

## 🔧 **Scripts**

### **SDK Introspector**
```
k8s_sdk_introspector.py
```
**Introspects Kubernetes Python SDK to extract field metadata**

Usage:
```bash
source ../venv/bin/activate
python3 k8s_sdk_introspector.py
```

Generates: `k8s_api_catalog_from_sdk.json`

### **Manual Catalog Generator**
```
k8s_api_catalog_generator.py
```
**Creates basic catalog from manual definitions**

Usage:
```bash
python3 k8s_api_catalog_generator.py
```

Generates: `k8s_api_catalog_enhanced.json`

---

## 📚 **Documentation**

### **SDK Catalog Report**
```
K8S_SDK_CATALOG_FINAL_REPORT.md
```
Complete documentation for the SDK-based catalog including:
- Statistics and metrics
- Field examples
- Integration guide
- Comparison with manual catalog

### **Manual Catalog Report**
```
K8S_API_CATALOG_REPORT.md
```
Documentation for the initial manual catalog

---

## 🎯 **Quick Start**

### **Use the Catalog in Your Code**

```python
import json

# Load the SDK-based catalog
with open('k8s_api_catalog_from_sdk.json') as f:
    catalog = json.load(f)

# Get Pod fields
pod = catalog['pod']
pod_list_op = pod['operations'][0]  # list operation

# Check a specific field
host_network = pod_list_op['item_fields']['spec']['nested_fields']['hostNetwork']
print(f"Field: hostNetwork")
print(f"Type: {host_network['type']}")                    # boolean
print(f"Security Impact: {host_network['security_impact']}")  # high
print(f"Operators: {host_network['operators']}")         # ['equals', 'not_equals']
```

### **Validate YAML Rule Field Paths**

```python
# Your YAML rule
# fields:
#   - path: item.hostNetwork
#     operator: equals
#     expected: false

# Validate it exists in catalog
field_path = ['spec', 'nested_fields', 'hostNetwork']
current = pod_list_op['item_fields']

for part in field_path:
    if part in current:
        current = current[part]
    else:
        print(f"❌ Field path not found: {part}")
        break
else:
    print(f"✅ Field exists: {current['type']}")
    if 'equals' in current['operators']:
        print(f"✅ Operator 'equals' is valid for {current['type']}")
```

---

## 📊 **Catalog Statistics**

| Metric | Count |
|--------|-------|
| **Resources** | 17 |
| **Operations** | 85 |
| **Fields** | 1,088 |
| **High-Security Fields** | 134 |
| **Compliance Categories** | 6 |

---

## 🔄 **Updating the Catalog**

If Kubernetes SDK updates or you need to regenerate:

```bash
cd /Users/apple/Desktop/threat-engine/k8_engine/Agent-ruleid-rule-yaml
source ../venv/bin/activate
python3 k8s_sdk_introspector.py
```

This will regenerate `k8s_api_catalog_from_sdk.json` with the latest SDK fields.

---

## 🆚 **Which Catalog to Use?**

| Use Case | Recommended File |
|----------|------------------|
| **Production compliance engine** | `k8s_api_catalog_from_sdk.json` ✅ |
| **Field validation** | `k8s_api_catalog_from_sdk.json` ✅ |
| **Rule generation** | `k8s_api_catalog_from_sdk.json` ✅ |
| **Reference/backup** | `k8s_api_catalog_enhanced.json` |

---

## 🔗 **Related Files**

The K8s engine uses this catalog in conjunction with:
- `../services/*/` - YAML rule definitions
- `../engine/engine_main.py` - Rule execution engine
- `../utils/cluster_namespace_discovery.py` - K8s SDK client

---

## 📝 **Integration with YAML Rules**

Your YAML rules in `../services/` can now be validated against the catalog:

**Example YAML Rule:**
```yaml
# services/pod/pod_rules.yaml
- check_id: k8s.pod.container.host_network_disabled
  for_each: list_pod_resources
  fields:
  - path: item.hostNetwork
    operator: equals
    expected: false
```

**Catalog Validation:**
```json
{
  "hostNetwork": {
    "type": "boolean",
    "sdk_attribute": "host_network",
    "compliance_category": "network",
    "security_impact": "high",
    "operators": ["equals", "not_equals"]
  }
}
```

✅ Field exists ✅ Type is boolean ✅ Operator 'equals' is valid

---

## ✨ **Key Features**

- ✅ **SDK-Accurate** - Fields match Kubernetes Python SDK exactly
- ✅ **Complete Metadata** - Types, categories, security impact
- ✅ **Nested Fields** - Full object hierarchy
- ✅ **Security Focus** - 134 high-impact fields identified
- ✅ **Type-Safe** - Operator validation by field type
- ✅ **Production-Ready** - Tested with K8s engine

---

**Last Updated**: 2025-12-13  
**K8s SDK Version**: Compatible with kubernetes-client  
**Status**: ✅ Production Ready

