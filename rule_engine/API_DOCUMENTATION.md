# Multi-CSP YAML Rule Builder - API Documentation

## Overview

The YAML Rule Builder API supports multiple Cloud Service Providers (CSPs) including AWS, Azure, GCP, OCI, AliCloud, and IBM Cloud. All API endpoints require explicit provider specification for multi-cloud support.

## Base URL

```
http://localhost:8000/api/v1
```

## Authentication

Currently, the API runs without authentication. In production, add authentication headers as needed.

## Provider Isolation

**Important**: Rules are isolated by provider. Rules for `aws.iam` will only match other `aws.iam` rules, not `azure.compute` rules, even if they have the same field + operator + value.

## API Endpoints

### 1. List Available Providers

Get list of all supported CSP providers.

**Endpoint**: `GET /api/v1/providers`

**Response**:
```json
{
  "providers": ["aws", "azure", "gcp", "oci", "alicloud", "ibm"]
}
```

**Example**:
```bash
curl http://localhost:8000/api/v1/providers
```

---

### 2. List Services for a Provider

Get all available services for a specific CSP provider.

**Endpoint**: `GET /api/v1/providers/{provider}/services`

**Path Parameters**:
- `provider` (required): Provider name (`aws`, `azure`, `gcp`, `oci`, `alicloud`, `ibm`)

**Response**:
```json
{
  "provider": "aws",
  "services": ["accessanalyzer", "account", "acm", "iam", "s3", ...]
}
```

**Example**:
```bash
# Get AWS services
curl http://localhost:8000/api/v1/providers/aws/services

# Get Azure services
curl http://localhost:8000/api/v1/providers/azure/services
```

---

### 3. List Fields for a Service

Get all available fields for a service in a specific provider, including their operators, types, and possible values.

**Endpoint**: `GET /api/v1/providers/{provider}/services/{service}/fields`

**Path Parameters**:
- `provider` (required): Provider name
- `service` (required): Service name (e.g., `iam`, `s3`)

**Response**:
```json
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
    "UserName": {
      "operators": ["equals", "not_equals", "contains"],
      "type": "string",
      "enum": false,
      "possible_values": null,
      "operations": ["ListUsers", "GetUser"]
    }
  }
}
```

**Example**:
```bash
# Get AWS IAM fields
curl http://localhost:8000/api/v1/providers/aws/services/iam/fields

# Get Azure Compute fields
curl http://localhost:8000/api/v1/providers/azure/services/compute/fields
```

---

### 4. Validate Rule

Validate a rule before generation. Uses two-phase comparison:
1. Phase 1: Match by provider + service + var + op + value (without for_each)
2. Phase 2: Refine match using for_each after dependency resolution

**Endpoint**: `POST /api/v1/rules/validate`

**Request Body**:
```json
{
  "provider": "aws",
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
```

**Response**:
```json
{
  "valid": true,
  "errors": [],
  "warnings": [],
  "existing_rules": [
    {
      "rule_id": "aws.iam.resource.existing_rule",
      "source_file": "/path/to/aws/iam/rules/iam.yaml",
      "for_each": "aws.iam.list_users",
      "note": "Phase 1 match found"
    }
  ]
}
```

**Example**:
```bash
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
```

---

### 5. Generate Rule

Generate YAML and metadata files for a rule. The rule will be **appended** to existing YAML files (merging capability).

**Endpoint**: `POST /api/v1/rules/generate`

**Request Body**:
```json
{
  "provider": "aws",
  "service": "iam",
  "title": "IAM User Status Check",
  "description": "Ensures IAM users have ACTIVE status",
  "remediation": "Activate the IAM user in AWS console",
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
```

**Multiple Conditions Example**:
```json
{
  "provider": "aws",
  "service": "iam",
  "title": "IAM User Complete Check",
  "description": "Ensures IAM user is active AND has MFA enabled",
  "remediation": "Activate user and enable MFA",
  "rule_id": "aws.iam.resource.user_active_with_mfa",
  "conditions": [
    {
      "field_name": "Status",
      "operator": "equals",
      "value": "ACTIVE"
    },
    {
      "field_name": "MFADevices",
      "operator": "exists",
      "value": null
    }
  ],
  "logical_operator": "all"
}
```

**Response**:
```json
{
  "success": true,
  "yaml_path": "/path/to/aws_compliance_python_engine/services/iam/rules/iam.yaml",
  "metadata_path": "/path/to/aws_compliance_python_engine/services/iam/metadata/aws.iam.resource.user_active.yaml",
  "existing_rules_found": [],
  "errors": []
}
```

**Example**:
```bash
curl -X POST http://localhost:8000/api/v1/rules/generate \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "aws",
    "service": "iam",
    "title": "IAM User Status Check",
    "description": "Ensures IAM users have ACTIVE status",
    "remediation": "Activate the IAM user",
    "rule_id": "aws.iam.resource.user_active",
    "conditions": [{
      "field_name": "Status",
      "operator": "equals",
      "value": "ACTIVE"
    }],
    "logical_operator": "single"
  }'
```

---

### 6. List All Rules

List all generated rules, optionally filtered by provider and service.

**Endpoint**: `GET /api/v1/rules`

**Query Parameters**:
- `provider` (optional): Filter by provider
- `service` (optional): Filter by service
- `limit` (optional, default: 100): Limit number of results
- `offset` (optional, default: 0): Pagination offset

**Response**:
```json
{
  "rules": [
    {
      "rule_id": "aws.iam.resource.user_active",
      "provider": "aws",
      "service": "iam",
      "title": "IAM User Status Check",
      "created_at": "2026-01-09T21:38:25.906974",
      "updated_at": "2026-01-09T21:38:25.906974"
    }
  ],
  "total": 150,
  "limit": 100,
  "offset": 0
}
```

**Example**:
```bash
# List all rules
curl http://localhost:8000/api/v1/rules

# List AWS rules only
curl http://localhost:8000/api/v1/rules?provider=aws

# List AWS IAM rules only
curl http://localhost:8000/api/v1/rules?provider=aws&service=iam
```

---

### 7. Get Specific Rule

Get details for a specific rule by rule_id.

**Endpoint**: `GET /api/v1/rules/{rule_id}`

**Path Parameters**:
- `rule_id` (required): Full rule ID (e.g., `aws.iam.resource.user_active`)

**Response**:
```json
{
  "rule_id": "aws.iam.resource.user_active",
  "provider": "aws",
  "service": "iam",
  "title": "IAM User Status Check",
  "description": "Ensures IAM users have ACTIVE status",
  "remediation": "Activate the IAM user",
  "conditions": [
    {
      "field_name": "Status",
      "operator": "equals",
      "value": "ACTIVE"
    }
  ],
  "logical_operator": "single",
  "yaml_path": "/path/to/iam.yaml",
  "metadata_path": "/path/to/metadata.yaml",
  "created_at": "2026-01-09T21:38:25.906974",
  "updated_at": "2026-01-09T21:38:25.906974"
}
```

**Example**:
```bash
curl http://localhost:8000/api/v1/rules/aws.iam.resource.user_active
```

---

### 8. Update Rule

Update an existing rule.

**Endpoint**: `PUT /api/v1/rules/{rule_id}`

**Path Parameters**:
- `rule_id` (required): Full rule ID

**Request Body**: Same as generate endpoint

**Example**:
```bash
curl -X PUT http://localhost:8000/api/v1/rules/aws.iam.resource.user_active \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "aws",
    "service": "iam",
    "title": "Updated Title",
    ...
  }'
```

---

### 9. Delete Rule

Delete a rule (removes from YAML and deletes metadata file).

**Endpoint**: `DELETE /api/v1/rules/{rule_id}`

**Path Parameters**:
- `rule_id` (required): Full rule ID

**Response**:
```json
{
  "rule_id": "aws.iam.resource.user_active",
  "status": "deleted",
  "message": "Rule deleted successfully"
}
```

**Example**:
```bash
curl -X DELETE http://localhost:8000/api/v1/rules/aws.iam.resource.user_active
```

---

### 10. Health Check

Check API health status.

**Endpoint**: `GET /api/v1/health`

**Response**:
```json
{
  "status": "healthy",
  "service": "yaml-rule-builder",
  "version": "1.0.0",
  "providers_enabled": ["aws", "azure", "gcp"]
}
```

**Example**:
```bash
curl http://localhost:8000/api/v1/health
```

---

## Multi-CSP Examples

### AWS Example

```bash
# 1. Get AWS services
curl http://localhost:8000/api/v1/providers/aws/services

# 2. Get IAM fields
curl http://localhost:8000/api/v1/providers/aws/services/iam/fields

# 3. Generate AWS rule
curl -X POST http://localhost:8000/api/v1/rules/generate \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "aws",
    "service": "iam",
    "title": "IAM User Active",
    "description": "Check IAM user status",
    "remediation": "Activate user",
    "rule_id": "aws.iam.resource.user_active",
    "conditions": [{
      "field_name": "Status",
      "operator": "equals",
      "value": "ACTIVE"
    }],
    "logical_operator": "single"
  }'
```

### Azure Example

```bash
# 1. Get Azure services
curl http://localhost:8000/api/v1/providers/azure/services

# 2. Get Compute fields
curl http://localhost:8000/api/v1/providers/azure/services/compute/fields

# 3. Generate Azure rule
curl -X POST http://localhost:8000/api/v1/rules/generate \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "azure",
    "service": "compute",
    "title": "VM Status Check",
    "description": "Check VM status",
    "remediation": "Start VM",
    "rule_id": "azure.compute.resource.vm_running",
    "conditions": [{
      "field_name": "Status",
      "operator": "equals",
      "value": "Running"
    }],
    "logical_operator": "single"
  }'
```

### GCP Example

```bash
# 1. Get GCP services
curl http://localhost:8000/api/v1/providers/gcp/services

# 2. Get Storage fields
curl http://localhost:8000/api/v1/providers/gcp/services/storage/fields

# 3. Generate GCP rule
curl -X POST http://localhost:8000/api/v1/rules/generate \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "gcp",
    "service": "storage",
    "title": "Bucket Public Access",
    "description": "Check bucket public access",
    "remediation": "Make bucket private",
    "rule_id": "gcp.storage.resource.bucket_private",
    "conditions": [{
      "field_name": "PublicAccess",
      "operator": "equals",
      "value": false
    }],
    "logical_operator": "single"
  }'
```

---

## Rule ID Format

Rule IDs must follow this format:

```
{provider}.{service}.{resource}.{rule_name}
```

**Examples**:
- `aws.iam.resource.user_active`
- `azure.compute.resource.vm_running`
- `gcp.storage.resource.bucket_private`
- `oci.identity.resource.user_mfa_enabled`

**Validation**: The `rule_id` prefix must match the `provider` parameter in the request.

---

## Logical Operators

- **`single`**: One condition (default if only one condition provided)
- **`all`**: All conditions must be true (AND logic)
- **`any`**: Any condition must be true (OR logic)

**Example with `all`**:
```json
{
  "conditions": [
    {"field_name": "Status", "operator": "equals", "value": "ACTIVE"},
    {"field_name": "MFADevices", "operator": "exists", "value": null}
  ],
  "logical_operator": "all"
}
```

**Example with `any`**:
```json
{
  "conditions": [
    {"field_name": "Status", "operator": "equals", "value": "ACTIVE"},
    {"field_name": "Status", "operator": "equals", "value": "CREATING"}
  ],
  "logical_operator": "any"
}
```

---

## Operators

Common operators supported:

- **`equals`**: Field equals value
- **`not_equals`**: Field does not equal value
- **`contains`**: Field contains value (for strings)
- **`exists`**: Field exists (value must be `null`)
- **`greater_than`**: Field > value (for numbers)
- **`less_than`**: Field < value (for numbers)
- **`greater_than_or_equal`**: Field >= value
- **`less_than_or_equal`**: Field <= value
- **`in`**: Field in list of values

**Note**: Available operators depend on the field type. Check field metadata using the fields endpoint.

---

## Error Responses

### 400 Bad Request

```json
{
  "detail": "provider is required"
}
```

### 404 Not Found

```json
{
  "detail": "Service 'invalid-service' not found for provider 'aws'"
}
```

### 500 Internal Server Error

```json
{
  "detail": "Error message here"
}
```

---

## Two-Phase Rule Comparison

The validation endpoint uses two-phase comparison:

1. **Phase 1 (Without for_each)**: 
   - Matches rules by: `provider + service + var + op + value`
   - Returns candidate matches (wider net)
   - Provider isolation enforced (only matches within same provider)

2. **Phase 2 (With for_each)**:
   - After dependency resolution, refines matches using `for_each` (discovery_id)
   - Returns exact match or None

This allows detecting duplicate rules even before resolving dependencies, then confirming exact matches after dependency resolution.

---

## YAML Merging

When generating rules, the system **merges** with existing YAML files:

- **Discovery entries**: Merged, avoiding duplicates by `discovery_id`
- **Check entries**: Appended, avoiding duplicates by `rule_id`
- **Existing content**: Preserved

This ensures that multiple rule generations don't overwrite existing rules but instead append to them.

---

## Python API Client Example

```python
from api import RuleBuilderAPI

# Initialize API
api = RuleBuilderAPI()

# Get providers
providers = api.get_providers()  # ['aws', 'azure', 'gcp', ...]

# Get services for AWS
aws_services = api.get_available_services("aws")

# Get fields for AWS IAM
iam_fields = api.get_service_fields("aws", "iam")

# Create and generate rule
from models.rule import Rule
from models.field_selection import FieldSelection

rule = Rule(
    rule_id="aws.iam.resource.test_rule",
    service="iam",
    provider="aws",
    title="Test Rule",
    description="Test description",
    remediation="Test remediation",
    conditions=[
        FieldSelection(
            field_name="Status",
            operator="equals",
            value="ACTIVE",
            rule_id="aws.iam.resource.test_rule"
        )
    ],
    logical_operator="single"
)

# Validate
validation = api.validate_rule(rule, "aws")
print(validation)

# Generate
result = api.generate_rule(rule, "aws")
print(result)
```

---

## Notes

1. **Provider Required**: All endpoints require explicit provider specification
2. **Provider Isolation**: Rules only match within the same provider
3. **YAML Merging**: Rules are appended to existing files, not overwritten
4. **Two-Phase Comparison**: Validation uses two-phase matching for better duplicate detection
5. **Rule ID Validation**: Rule IDs must start with provider prefix (e.g., `aws.` for AWS)

