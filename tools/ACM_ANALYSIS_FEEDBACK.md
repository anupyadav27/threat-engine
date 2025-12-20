# ACM Service Analysis - Agentic AI Improvement Feedback

## Scan Results Summary
- **Service**: ACM
- **Total Checks**: 140
- **Passed**: 0
- **Failed**: 140
- **Errors**: 0
- **Discoveries Executed**: 0 (all 5 discoveries not executed)

## Critical Issues Identified

### 1. Discoveries Not Executed
All 5 discoveries were marked as "not executed":
- `aws.acm.list_certificates`
- `aws.acm.describe_certificate`
- `aws.acm.get_certificate`
- `aws.acm.list_tags_for_certificate`
- `aws.acm.get_account_configuration`

**Root Cause Analysis:**
- The scan log shows validation errors: `Value of the input at 'certificateArn' failed to satisfy constraint`
- This suggests parameter mapping issues in dependent discoveries
- However, if `list_certificates` didn't execute, dependent discoveries can't run

**Possible Causes:**
1. **YAML Structure Issues**: Missing required fields or syntax errors
2. **Action Name Mismatch**: `action` field doesn't match boto3 method name
3. **Service Scope**: ACM is a global service, may need special handling

### 2. Parameter Mapping Validation Errors

From scan log:
```
Failed describe_certificate: Value of the input at 'certificateArn' failed to satisfy 
constraint: Member must satisfy regular expression pattern: arn:[\w+=/,.@-]+:acm:...
```

**Issue Identified:**
- The rules file uses: `CertificateArn: '{{ item.certificate_arn }}'`
- The emit field is: `certificate_arn: '{{ resource.CertificateArn }}'`
- The operation registry confirms: `acm.certificate_arn` from `CertificateSummaryList[].CertificateArn`

**Root Cause:**
- Field mapping appears correct
- But validation error suggests the ARN value is invalid or empty
- This could mean:
  1. `list_certificates` returned empty (no certificates in account)
  2. The `certificate_arn` field is not being extracted correctly
  3. The template resolution is failing

### 3. Service Scope Handling

ACM is a **global service** (no region required), but the rules file may not handle this correctly.

**Current Rules File:**
```yaml
services:
  client: acm
  module: boto3.client
```

**Issue:**
- No explicit region handling
- Global services should use `region_name='us-east-1'` or handle region differently

## Actionable Improvements for Agentic AI Generator

### Improvement 1: Validate Discovery Structure Before Generation

**Current Issue:** Discoveries not executing suggests structural problems

**Fix in `generate_rules.py`:**
```python
def validate_discovery(discovery: dict) -> List[str]:
    """Validate discovery structure and return list of errors"""
    errors = []
    
    # Required fields
    required = ['discovery_id', 'calls', 'emit']
    for field in required:
        if field not in discovery:
            errors.append(f"Missing required field: {field}")
    
    # Validate calls
    if 'calls' in discovery:
        for i, call in enumerate(discovery['calls']):
            if 'action' not in call:
                errors.append(f"Call {i} missing 'action' field")
            # Validate action name matches boto3 method
            action = call.get('action')
            if action and not validate_boto3_action(service_name, action):
                errors.append(f"Invalid action: {action} (not a valid boto3 method)")
    
    # Validate emit
    if 'emit' in discovery:
        emit = discovery['emit']
        if 'items_for' not in emit and 'item' not in emit:
            errors.append("Emit must have either 'items_for' or 'item'")
    
    return errors
```

### Improvement 2: Verify Parameter Field Existence

**Current Issue:** Parameters reference fields that may not exist in parent discovery

**Fix in `generate_rules.py`:**
```python
def validate_parameter_mapping(discovery: dict, parent_discovery: dict) -> List[str]:
    """Validate that parameters reference existing fields from parent"""
    errors = []
    
    if 'for_each' not in discovery:
        return errors  # Not a dependent discovery
    
    params = {}
    for call in discovery.get('calls', []):
        params.update(call.get('params', {}))
    
    # Get parent emit fields
    parent_emit = parent_discovery.get('emit', {})
    parent_fields = set()
    
    if 'item' in parent_emit:
        parent_fields.update(parent_emit['item'].keys())
    if 'items_for' in parent_emit and 'item' in parent_emit:
        parent_fields.update(parent_emit['item'].keys())
    
    # Check each parameter template
    for param_name, param_template in params.items():
        # Extract field reference from template: {{ item.field_name }}
        field_match = re.search(r'\{\{\s*item\.(\w+)\s*\}\}', param_template)
        if field_match:
            field_name = field_match.group(1)
            if field_name not in parent_fields:
                errors.append(
                    f"Parameter {param_name} references field '{field_name}' "
                    f"not found in parent discovery emit fields: {list(parent_fields)}"
                )
    
    return errors
```

### Improvement 3: Handle Global Services Correctly

**Current Issue:** Global services may need special region handling

**Fix in `generate_rules.py`:**
```python
def get_service_scope(service_name: str) -> str:
    """Determine if service is global or regional"""
    # Load service config or use known global services
    global_services = ['acm', 'iam', 'cloudfront', 'route53', 's3']
    return 'global' if service_name in global_services else 'regional'

def generate_service_config(service_name: str) -> dict:
    """Generate service configuration with proper scope handling"""
    scope = get_service_scope(service_name)
    
    config = {
        'client': service_name,
        'module': 'boto3.client'
    }
    
    if scope == 'global':
        # Global services typically use us-east-1
        config['region'] = 'us-east-1'
    
    return config
```

### Improvement 4: Add Pre-Execution Validation

**Current Issue:** Issues only discovered after running engine

**Fix:** Add validation step before generating final YAML:
```python
def validate_generated_rules(rules: dict) -> dict:
    """Validate generated rules and return validation report"""
    report = {
        'errors': [],
        'warnings': [],
        'valid': True
    }
    
    discoveries = rules.get('discovery', [])
    
    # Check each discovery
    for discovery in discoveries:
        # Validate structure
        errors = validate_discovery(discovery)
        report['errors'].extend(errors)
        
        # Check dependencies
        if 'for_each' in discovery:
            dep_id = discovery['for_each']
            parent = next((d for d in discoveries if d['discovery_id'] == dep_id), None)
            if not parent:
                report['errors'].append(
                    f"Discovery {discovery['discovery_id']} depends on "
                    f"non-existent discovery: {dep_id}"
                )
            else:
                # Validate parameter mapping
                param_errors = validate_parameter_mapping(discovery, parent)
                report['errors'].extend(param_errors)
    
    report['valid'] = len(report['errors']) == 0
    return report
```

### Improvement 5: Improve Field Name Matching

**Current Issue:** Field name mismatches between emit and params

**Fix:** Use operation registry to verify field mappings:
```python
def verify_field_mapping(
    operation_name: str,
    param_name: str,
    emit_field_name: str,
    operation_registry: dict
) -> bool:
    """Verify that emit field correctly maps to operation parameter"""
    op = operation_registry.get('operations', {}).get(operation_name)
    if not op:
        return False
    
    # Check if param exists in consumes
    consumes = op.get('consumes', [])
    param_entity = next(
        (c for c in consumes if c.get('param') == param_name),
        None
    )
    
    if not param_entity:
        return False
    
    # Check if emit field matches the entity
    expected_entity = param_entity.get('entity')
    # Convert entity to field name (e.g., acm.certificate_arn -> certificate_arn)
    expected_field = expected_entity.split('.')[-1] if '.' in expected_entity else expected_entity
    
    return emit_field_name == expected_field or emit_field_name in expected_entity
```

## Recommended Next Steps

1. **Add Validation Layer**: Implement pre-generation validation in `generate_rules.py`
2. **Test with Empty Results**: Handle cases where list operations return no items
3. **Improve Error Messages**: Make validation errors more actionable
4. **Add Service Scope Detection**: Automatically detect and handle global vs regional services
5. **Verify Field Mappings**: Cross-reference with operation registry during generation

## Testing Checklist

After implementing improvements, verify:
- [ ] All discoveries execute successfully
- [ ] Parameter mappings are correct (no validation errors)
- [ ] Global services handled correctly
- [ ] Empty result sets handled gracefully
- [ ] Field names match between emit and params
- [ ] Dependency chains are valid (no circular dependencies)

## Example Fixed Discovery

```yaml
- discovery_id: aws.acm.describe_certificate
  calls:
  - action: describe_certificate
    save_as: response
    params:
      CertificateArn: '{{ item.certificate_arn }}'  # ✅ Verified: certificate_arn exists in parent
  for_each: aws.acm.list_certificates
  on_error: continue
  emit:
    item:
      certificate_arn: '{{ response.Certificate.CertificateArn }}'  # ✅ Verified: matches API response
      # ... other fields
```

