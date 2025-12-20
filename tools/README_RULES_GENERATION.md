# Rules Generation - Agentic AI Platform

## Overview

This tool generates compliance rules YAML files from service operation registries. It automatically creates discovery items with proper dependency chains (for_each relationships).

## Current Status

✅ **Working Features:**
- Discovery generation from read operations
- Dependency chain detection (for_each relationships)
- Parameter mapping from dependencies
- Proper discovery ordering (dependencies first)
- YAML output with correct structure

⚠️ **In Progress:**
- Check generation (needs LLM integration)
- Field name optimization
- Emit structure refinement

## Usage

### Generate Rules for Single Service

```bash
python tools/generate_rules.py pythonsdk-database/aws/<service>
```

**Example:**
```bash
python tools/generate_rules.py pythonsdk-database/aws/acm
```

### Output

Generates: `aws_compliance_python_engine/services/<service>/rules/<service>.yaml`

**Backup:** Creates `.yaml.bak` before overwriting existing files.

## How It Works

### 1. Discovery Generation

**From operation_registry.json:**
- Identifies `read_list` and `read_get` operations
- Maps operations to boto3 methods
- Extracts `produces` to build `emit` sections
- Handles list vs single item operations

**Example:**
```json
// operation_registry.json
{
  "ListCertificates": {
    "kind": "read_list",
    "produces": [
      {"entity": "acm.certificate_arn", "path": "CertificateSummaryList[].CertificateArn", "source": "item"}
    ]
  }
}
```

```yaml
# Generated discovery
- discovery_id: aws.acm.list_certificates
  calls:
    - action: list_certificates
      save_as: response
  emit:
    items_for: '{{ response.CertificateSummaryList }}'
    as: resource
    item:
      certificate_arn: '{{ resource.CertificateArn }}'
```

### 2. Dependency Chain Detection

**From adjacency.json:**
- Analyzes `op_consumes` to find dependencies
- Maps consumed entities to producing operations
- Creates `for_each` relationships
- Orders discoveries (dependencies first)

**Example:**
```json
// adjacency.json
{
  "op_consumes": {
    "DescribeCertificate": ["acm.certificate_arn"]
  },
  "entity_producers": {
    "acm.certificate_arn": ["ListCertificates"]
  }
}
```

```yaml
# Generated with dependency
- discovery_id: aws.acm.describe_certificate
  calls:
    - action: describe_certificate
      params:
        CertificateArn: '{{ item.certificate_arn }}'
  for_each: aws.acm.list_certificates
  on_error: continue
```

### 3. Parameter Mapping

**Entity to Field Mapping:**
- Uses `produces` from dependency operation
- Maps entity to field path
- Creates parameter templates

**Example:**
- Dependency produces: `acm.certificate_arn` from `CertificateSummaryList[].CertificateArn`
- Maps to: `item.certificate_arn` (from emit)
- Creates param: `CertificateArn: '{{ item.certificate_arn }}'`

## Generated Structure

```yaml
version: '1.0'
provider: aws
service: <service>
services:
  client: <service>
  module: boto3.client
discovery:
  # Root discoveries (no dependencies)
  - discovery_id: aws.<service>.<operation>
    calls:
      - action: <boto3_method>
        save_as: response
    emit:
      items_for: '{{ response.List }}'  # for list operations
      as: resource
      item: {...}
  
  # Dependent discoveries
  - discovery_id: aws.<service>.<operation>
    calls:
      - action: <boto3_method>
        params:
          ParamName: '{{ item.field }}'
    for_each: aws.<service>.<dependency>
    on_error: continue
    emit:
      item: {...}
checks: []  # Generated separately (LLM-based)
```

## Dependency Chain Examples

### Simple Chain (2 levels)
```
ListCertificates (root)
  └─ DescribeCertificate (depends on ListCertificates)
     └─ GetCertificateDetails (depends on DescribeCertificate)
```

### Multiple Dependencies
```
ListBuckets (root)
  ├─ GetBucketPolicy (depends on ListBuckets)
  ├─ GetBucketEncryption (depends on ListBuckets)
  └─ GetBucketLogging (depends on ListBuckets)
```

## Next Steps

### Immediate Improvements

1. **Field Name Mapping**
   - Better entity-to-field mapping
   - Use source spec field metadata
   - Match API response structure exactly

2. **Check Generation**
   - Integrate LLM for check generation
   - Use compliance pattern library
   - Generate appropriate conditions

3. **Emit Structure**
   - Optimize emit fields
   - Remove unnecessary fields
   - Match existing rules format

### Future Enhancements

1. **LLM Integration**
   - Planner agent for operation analysis
   - Generator agent for check creation
   - Validator agent for quality assurance

2. **Pattern Library**
   - Common compliance patterns
   - Service-specific patterns
   - Pattern matching and application

3. **Batch Processing**
   - Process all services
   - Progress tracking
   - Error handling and reporting

## Testing

Tested on:
- ✅ ACM (5 discoveries, 3 dependency chains)
- ⬜ S3 (to be tested)
- ⬜ IAM (to be tested)

## Known Issues

1. **Check Generation**: Currently empty - needs LLM integration
2. **Field Mapping**: Some fields may not match API exactly
3. **Emit Optimization**: Could be more selective about fields

## Files

- `tools/generate_rules.py` - Main generation script
- `tools/README_RULES_GENERATION.md` - This file
- `AGENTIC_AI_RULES_GENERATION_REVIEW.md` - Full architecture review

---

**Status**: Discovery generation working, check generation pending LLM integration
**Last Updated**: 2024-12-19

