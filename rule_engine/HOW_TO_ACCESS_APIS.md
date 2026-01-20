# How to Access Different APIs - Complete Guide

## Overview

The YAML Rule Builder provides multiple API interfaces for different use cases:
1. **Python API** (`api.py`) - For programmatic access from Python
2. **REST API** (`api_server.py`) - For web/UI integration via FastAPI
3. **CLI** (`cli.py`) - For command-line usage

## 1. Python API (`api.py`)

### Import and Initialize

```python
from api import RuleBuilderAPI

# Initialize API (no provider required at init)
api = RuleBuilderAPI()
```

### Available Methods

#### List Providers
```python
providers = api.get_providers()
# Returns: ['aws', 'azure', 'gcp', 'oci', 'alicloud', 'ibm']
```

#### List Services for Provider
```python
# Provider is REQUIRED
aws_services = api.get_available_services("aws")
# Returns: ['accessanalyzer', 'account', 'acm', ...]

azure_services = api.get_available_services("azure")
gcp_services = api.get_available_services("gcp")
```

#### List Fields for Service
```python
# Both provider and service are REQUIRED
iam_fields = api.get_service_fields("aws", "iam")
# Returns: {
#   "Status": {
#     "operators": ["equals", "not_equals", "in"],
#     "type": "string",
#     "enum": True,
#     "possible_values": ["ACTIVE", "CREATING", "DISABLED"],
#     "operations": ["ListUsers", "GetUser"]
#   },
#   ...
# }
```

#### Create Rule from UI Input
```python
from models.rule import Rule

# Provider can be in input or extracted from rule_id
rule = api.create_rule_from_ui_input({
    "provider": "aws",  # REQUIRED (or extracted from rule_id)
    "service": "iam",
    "title": "IAM User Active",
    "description": "Ensures IAM users are active",
    "remediation": "Activate the user",
    "rule_id": "aws.iam.resource.user_active",  # Must start with provider prefix
    "conditions": [
        {
            "field_name": "Status",
            "operator": "equals",
            "value": "ACTIVE"
        }
    ],
    "logical_operator": "single"  # or "all" or "any"
})
```

#### Validate Rule
```python
# Provider is REQUIRED
validation = api.validate_rule(rule, "aws")
# Returns: {
#   "valid": True,
#   "errors": [],
#   "warnings": [],
#   "existing_rules": []  # Two-phase matching results
# }
```

#### Generate Rule
```python
# Provider is REQUIRED
result = api.generate_rule(rule, "aws", create_metadata=True)
# Returns: {
#   "success": True,
#   "yaml_path": "/path/to/iam.yaml",
#   "metadata_path": "/path/to/metadata.yaml",
#   "existing_rules_found": [],
#   "errors": []
# }
# Note: YAML file is merged with existing file (not overwritten)
```

### Complete Python Example

```python
from api import RuleBuilderAPI

api = RuleBuilderAPI()

# 1. List providers
providers = api.get_providers()
print(f"Available providers: {providers}")

# 2. List AWS services
aws_services = api.get_available_services("aws")
print(f"AWS services: {aws_services[:5]}")

# 3. List IAM fields
iam_fields = api.get_service_fields("aws", "iam")
print(f"IAM fields: {list(iam_fields.keys())[:5]}")

# 4. Create rule with multiple conditions
rule = api.create_rule_from_ui_input({
    "provider": "aws",
    "service": "iam",
    "title": "IAM User Active with MFA",
    "description": "Ensures IAM user is active and has MFA",
    "remediation": "Activate user and enable MFA",
    "rule_id": "aws.iam.resource.user_active_mfa",
    "conditions": [
        {"field_name": "Status", "operator": "equals", "value": "ACTIVE"},
        {"field_name": "MFADevices", "operator": "exists", "value": None}
    ],
    "logical_operator": "all"
})

# 5. Validate rule
validation = api.validate_rule(rule, "aws")
if validation["valid"]:
    print("✓ Rule is valid")
    if validation["existing_rules"]:
        print(f"⚠ Found {len(validation['existing_rules'])} existing rules")
else:
    print(f"✗ Validation failed: {validation['errors']}")

# 6. Generate rule (merges with existing YAML)
result = api.generate_rule(rule, "aws", create_metadata=True)
if result["success"]:
    print(f"✓ Rule generated: {result['yaml_path']}")
    print(f"✓ Metadata: {result['metadata_path']}")
else:
    print(f"✗ Generation failed: {result['errors']}")
```

---

## 2. REST API (`api_server.py`)

### Start the Server

```bash
cd yaml-rule-builder
python3 api_server.py
# Or with uvicorn:
uvicorn api_server:app --host 0.0.0.0 --port 8000
```

Server runs at: `http://localhost:8000`

### Available Endpoints

#### Provider Endpoints

**List Providers**
```bash
GET /api/v1/providers

# Example
curl http://localhost:8000/api/v1/providers

# Response
{
  "providers": ["aws", "azure", "gcp", "oci", "alicloud", "ibm"]
}
```

**List Services for Provider**
```bash
GET /api/v1/providers/{provider}/services

# Example
curl http://localhost:8000/api/v1/providers/aws/services

# Response
{
  "provider": "aws",
  "services": ["accessanalyzer", "account", "acm", ...]
}
```

**List Fields for Service**
```bash
GET /api/v1/providers/{provider}/services/{service}/fields

# Example
curl http://localhost:8000/api/v1/providers/aws/services/iam/fields

# Response
{
  "provider": "aws",
  "service": "iam",
  "fields": {
    "Status": {
      "operators": ["equals", "not_equals", "in"],
      "type": "string",
      "enum": true,
      "possible_values": ["ACTIVE", "CREATING", "DISABLED"],
      "operations": ["ListUsers", "GetUser"]
    },
    ...
  }
}
```

#### Rule Endpoints

**Validate Rule**
```bash
POST /api/v1/rules/validate
Content-Type: application/json

# Request Body
{
  "provider": "aws",  # REQUIRED
  "service": "iam",
  "rule_id": "aws.iam.resource.test_rule",
  "conditions": [
    {
      "field_name": "Status",
      "operator": "equals",
      "value": "ACTIVE"
    }
  ],
  "logical_operator": "single"
}

# Example
curl -X POST http://localhost:8000/api/v1/rules/validate \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "aws",
    "service": "iam",
    "rule_id": "aws.iam.resource.test_rule",
    "conditions": [{
      "field_name": "Status",
      "operator": "equals",
      "value": "ACTIVE"
    }],
    "logical_operator": "single"
  }'

# Response
{
  "valid": true,
  "errors": [],
  "warnings": [],
  "existing_rules": []
}
```

**Generate Rule**
```bash
POST /api/v1/rules/generate
Content-Type: application/json

# Request Body
{
  "provider": "aws",  # REQUIRED
  "service": "iam",
  "title": "IAM User Active",
  "description": "Ensures IAM users are active",
  "remediation": "Activate the user",
  "rule_id": "aws.iam.resource.user_active",
  "conditions": [
    {
      "field_name": "Status",
      "operator": "equals",
      "value": "ACTIVE"
    }
  ],
  "logical_operator": "single"
}

# Example with Multiple Conditions
curl -X POST http://localhost:8000/api/v1/rules/generate \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "aws",
    "service": "iam",
    "title": "IAM User Complete",
    "description": "User is active and has MFA",
    "remediation": "Activate user and enable MFA",
    "rule_id": "aws.iam.resource.user_complete",
    "conditions": [
      {"field_name": "Status", "operator": "equals", "value": "ACTIVE"},
      {"field_name": "MFADevices", "operator": "exists", "value": null}
    ],
    "logical_operator": "all"
  }'

# Response
{
  "success": true,
  "yaml_path": "/path/to/iam.yaml",
  "metadata_path": "/path/to/metadata.yaml",
  "existing_rules_found": [],
  "errors": []
}
```

**List All Rules**
```bash
GET /api/v1/rules?provider={provider}&service={service}&limit=100&offset=0

# Examples
curl http://localhost:8000/api/v1/rules
curl http://localhost:8000/api/v1/rules?provider=aws
curl http://localhost:8000/api/v1/rules?provider=aws&service=iam
```

**Get Specific Rule**
```bash
GET /api/v1/rules/{rule_id}

# Example
curl http://localhost:8000/api/v1/rules/aws.iam.resource.user_active
```

**Update Rule**
```bash
PUT /api/v1/rules/{rule_id}
Content-Type: application/json

# Request Body: Same as generate
```

**Delete Rule**
```bash
DELETE /api/v1/rules/{rule_id}

# Example
curl -X DELETE http://localhost:8000/api/v1/rules/aws.iam.resource.user_active
```

**List Service Rules**
```bash
GET /api/v1/providers/{provider}/services/{service}/rules

# Example
curl http://localhost:8000/api/v1/providers/aws/services/iam/rules
```

**Health Check**
```bash
GET /api/v1/health

# Example
curl http://localhost:8000/api/v1/health

# Response
{
  "status": "healthy",
  "service": "yaml-rule-builder",
  "version": "1.0.0",
  "providers_enabled": ["aws", "azure", "gcp", "oci", "alicloud", "ibm"]
}
```

### Complete REST API Example (JavaScript/Fetch)

```javascript
// List providers
const providers = await fetch('http://localhost:8000/api/v1/providers')
  .then(r => r.json());

// List AWS services
const awsServices = await fetch('http://localhost:8000/api/v1/providers/aws/services')
  .then(r => r.json());

// List IAM fields
const iamFields = await fetch('http://localhost:8000/api/v1/providers/aws/services/iam/fields')
  .then(r => r.json());

// Generate rule
const result = await fetch('http://localhost:8000/api/v1/rules/generate', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    provider: 'aws',
    service: 'iam',
    title: 'IAM User Active',
    description: 'Ensures IAM users are active',
    remediation: 'Activate the user',
    rule_id: 'aws.iam.resource.user_active',
    conditions: [{
      field_name: 'Status',
      operator: 'equals',
      value: 'ACTIVE'
    }],
    logical_operator: 'single'
  })
}).then(r => r.json());

console.log('Generated:', result);
```

---

## 3. CLI (`cli.py`)

### Basic Commands

**List Services** (defaults to AWS)
```bash
python3 cli.py list-services
# Or with provider (when implemented):
python3 cli.py list-services --provider aws
```

**List Fields** (defaults to AWS)
```bash
python3 cli.py list-fields --service iam
# Or with provider (when implemented):
python3 cli.py list-fields --provider aws --service iam
```

**Generate Rule** (Interactive mode)
```bash
python3 cli.py generate --service iam
# Or with provider (when implemented):
python3 cli.py generate --provider aws --service iam
```

**Generate Rule** (From JSON)
```bash
python3 cli.py generate --service iam --input rules.json --output iam.yaml
# Or with provider (when implemented):
python3 cli.py generate --provider aws --service iam --input rules.json
```

### JSON Input Format

```json
{
  "provider": "aws",
  "service": "iam",
  "rule_id": "aws.iam.resource.test_rule",
  "field_name": "Status",
  "operator": "equals",
  "value": "ACTIVE",
  "title": "IAM User Active",
  "description": "Ensures IAM users are active",
  "remediation": "Activate the user"
}
```

Or for multiple rules:
```json
[
  {
    "provider": "aws",
    "service": "iam",
    "rule_id": "aws.iam.resource.rule1",
    "field_name": "Status",
    "operator": "equals",
    "value": "ACTIVE",
    ...
  },
  {
    "provider": "aws",
    "service": "iam",
    "rule_id": "aws.iam.resource.rule2",
    ...
  }
]
```

---

## 4. Multi-CSP Examples

### AWS Example
```python
from api import RuleBuilderAPI

api = RuleBuilderAPI()

# AWS-specific operations
aws_services = api.get_available_services("aws")
iam_fields = api.get_service_fields("aws", "iam")

rule = api.create_rule_from_ui_input({
    "provider": "aws",
    "service": "iam",
    "rule_id": "aws.iam.resource.user_active",
    ...
})

result = api.generate_rule(rule, "aws")
```

### Azure Example (When Adapter Implemented)
```python
from api import RuleBuilderAPI

api = RuleBuilderAPI()

# Azure-specific operations
azure_services = api.get_available_services("azure")
compute_fields = api.get_service_fields("azure", "compute")

rule = api.create_rule_from_ui_input({
    "provider": "azure",
    "service": "compute",
    "rule_id": "azure.compute.resource.vm_running",
    ...
})

result = api.generate_rule(rule, "azure")
```

### GCP Example (When Adapter Implemented)
```python
from api import RuleBuilderAPI

api = RuleBuilderAPI()

# GCP-specific operations
gcp_services = api.get_available_services("gcp")
storage_fields = api.get_service_fields("gcp", "storage")

rule = api.create_rule_from_ui_input({
    "provider": "gcp",
    "service": "storage",
    "rule_id": "gcp.storage.resource.bucket_private",
    ...
})

result = api.generate_rule(rule, "gcp")
```

---

## 5. Error Handling

### Python API Errors

```python
from api import RuleBuilderAPI

api = RuleBuilderAPI()

try:
    # Missing provider will raise ValueError
    services = api.get_available_services(None)
except ValueError as e:
    print(f"Error: {e}")  # "provider parameter is required"

try:
    # Invalid provider will raise ValueError
    services = api.get_available_services("invalid_provider")
except ValueError as e:
    print(f"Error: {e}")  # "Provider 'invalid_provider' is not supported"

try:
    # Invalid service will raise ValueError
    fields = api.get_service_fields("aws", "invalid_service")
except ValueError as e:
    print(f"Error: {e}")  # "Service 'invalid_service' not found..."

try:
    # Provider mismatch will be caught in validation
    rule = api.create_rule_from_ui_input({
        "provider": "aws",
        "rule_id": "azure.compute.resource.test",  # Mismatch!
        ...
    })
except ValueError as e:
    print(f"Error: {e}")  # "rule_id must start with provider prefix"
```

### REST API Errors

**400 Bad Request**
```json
{
  "detail": "provider is required"
}
```

**404 Not Found**
```json
{
  "detail": "Service 'invalid-service' not found for provider 'aws'"
}
```

**500 Internal Server Error**
```json
{
  "detail": "Error message here"
}
```

---

## 6. Provider-Specific Considerations

### AWS
- Provider: `"aws"`
- Rule ID prefix: `"aws."`
- Database path: `pythonsdk-database/aws/`
- Output path: `aws_compliance_python_engine/services/`
- Dependencies file: `boto3_dependencies_with_python_names_fully_enriched.json`
- SDK module: `boto3.client`
- Documentation: `https://docs.aws.amazon.com/{service}/latest/userguide/`

### Azure (When Implemented)
- Provider: `"azure"`
- Rule ID prefix: `"azure."`
- Database path: `pythonsdk-database/azure/`
- Output path: `azure_compliance_python_engine/services/`
- Dependencies file: `azure_dependencies_with_python_names_fully_enriched.json`
- SDK module: `azure.mgmt.{service}.{Service}ManagementClient`
- Documentation: `https://learn.microsoft.com/en-us/azure/{service}/`

### GCP (When Implemented)
- Provider: `"gcp"`
- Rule ID prefix: `"gcp."`
- Database path: `pythonsdk-database/gcp/`
- Output path: `gcp_compliance_python_engine/services/`
- Dependencies file: `gcp_dependencies_with_python_names_fully_enriched.json`
- SDK module: `googleapiclient.discovery.build`
- Documentation: `https://cloud.google.com/{service}/docs`

---

## 7. Testing

### Test Script
```bash
cd yaml-rule-builder
python3 test_aws_backward_compat.py
```

### Manual Testing
```python
from api import RuleBuilderAPI

api = RuleBuilderAPI()

# Quick test
providers = api.get_providers()
print(f"Providers: {providers}")

services = api.get_available_services("aws")
print(f"AWS services: {len(services)}")

fields = api.get_service_fields("aws", "account")
print(f"Account fields: {len(fields)}")
```

---

## 8. Integration with UI

### Recommended Flow

1. **Service Selection**: User selects provider → list services for that provider
2. **Field Selection**: User selects service → list fields for that service
3. **Operator Selection**: Show operators from field metadata
4. **Value Input**: Show enum values if available, or text input
5. **Multiple Conditions**: Allow adding multiple field+operator+value pairs
6. **Logical Operator**: Radio buttons for "all" (AND) or "any" (OR)
7. **Metadata Input**: Text areas for title, description, remediation
8. **Validation**: Call validate endpoint before generation
9. **Generation**: Call generate endpoint to create files

### UI Integration Example

```javascript
class RuleBuilderUI {
  constructor(apiBaseUrl = 'http://localhost:8000/api/v1') {
    this.apiBaseUrl = apiBaseUrl;
  }
  
  async listProviders() {
    const res = await fetch(`${this.apiBaseUrl}/providers`);
    const data = await res.json();
    return data.providers;
  }
  
  async listServices(provider) {
    const res = await fetch(`${this.apiBaseUrl}/providers/${provider}/services`);
    const data = await res.json();
    return data.services;
  }
  
  async listFields(provider, service) {
    const res = await fetch(`${this.apiBaseUrl}/providers/${provider}/services/${service}/fields`);
    const data = await res.json();
    return data.fields;
  }
  
  async validateRule(ruleData) {
    const res = await fetch(`${this.apiBaseUrl}/rules/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(ruleData)
    });
    return await res.json();
  }
  
  async generateRule(ruleData) {
    const res = await fetch(`${this.apiBaseUrl}/rules/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(ruleData)
    });
    return await res.json();
  }
}

// Usage
const ui = new RuleBuilderUI();

// Get providers for dropdown
const providers = await ui.listProviders();

// User selects AWS
const awsServices = await ui.listServices('aws');

// User selects IAM
const iamFields = await ui.listFields('aws', 'iam');

// User builds rule
const ruleData = {
  provider: 'aws',
  service: 'iam',
  rule_id: 'aws.iam.resource.user_active',
  title: 'IAM User Active',
  description: 'Description',
  remediation: 'Remediation',
  conditions: [{
    field_name: 'Status',
    operator: 'equals',
    value: 'ACTIVE'
  }],
  logical_operator: 'single'
};

// Validate first
const validation = await ui.validateRule(ruleData);
if (validation.valid) {
  // Generate
  const result = await ui.generateRule(ruleData);
  console.log('Rule generated:', result);
}
```

---

## Summary

### Quick Reference

| Operation | Python API | REST API | CLI |
|-----------|-----------|----------|-----|
| List Providers | `api.get_providers()` | `GET /api/v1/providers` | N/A |
| List Services | `api.get_available_services(provider)` | `GET /api/v1/providers/{provider}/services` | `list-services --provider {provider}` |
| List Fields | `api.get_service_fields(provider, service)` | `GET /api/v1/providers/{provider}/services/{service}/fields` | `list-fields --provider {provider} --service {service}` |
| Validate Rule | `api.validate_rule(rule, provider)` | `POST /api/v1/rules/validate` | N/A |
| Generate Rule | `api.generate_rule(rule, provider)` | `POST /api/v1/rules/generate` | `generate --provider {provider} --service {service}` |

### Key Points

1. **Provider is REQUIRED** in all API calls (explicit, not inferred)
2. **Rule ID must match provider prefix** (e.g., `aws.` for AWS)
3. **Provider isolation** - Rules only compared within same provider
4. **YAML merging** - New rules appended to existing files (not overwritten)
5. **Two-phase matching** - Better duplicate detection with for_each refinement
6. **Multiple conditions** - Support for all (AND) and any (OR) logic

---

For complete API documentation, see: `API_DOCUMENTATION.md`

