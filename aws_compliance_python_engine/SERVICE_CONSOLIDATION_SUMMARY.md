# Service Consolidation Summary

## Overview
Consolidated services that share the same boto3 client into single YAML files for cleaner organization.

## Consolidated Services

### 1. EC2 Client (`ec2.yaml`)
**Consolidates:** `ec2`, `eip`, `vpc`, `vpcflowlogs`

- **Total:** 49 discoveries, 224 checks
  - `ec2`: 32 discoveries, 169 checks
  - `eip`: 1 discovery, 1 check
  - `vpc`: 15 discoveries, 50 checks
  - `vpcflowlogs`: 1 discovery, 4 checks

### 2. ECS Client (`ecs.yaml`)
**Consolidates:** `ecs`, `fargate`

- **Total:** 7 discoveries, 18 checks
  - `ecs`: 3 discoveries, 8 checks
  - `fargate`: 4 discoveries, 10 checks

### 3. Firehose Client (`firehose.yaml`)
**Consolidates:** `firehose`, `kinesisfirehose`

- **Total:** 4 discoveries, 7 checks
  - `firehose`: 1 discovery, 1 check
  - `kinesisfirehose`: 3 discoveries, 6 checks

### 4. SSM Client (`ssm.yaml`)
**Consolidates:** `ssm`, `parameterstore`

- **Total:** 10 discoveries, 22 checks
  - `ssm`: 9 discoveries, 17 checks
  - `parameterstore`: 1 discovery, 5 checks

### 5. Step Functions Client (`stepfunctions.yaml`)
**Consolidates:** `stepfunctions`, `workflows`

- **Total:** 7 discoveries, 38 checks
  - `stepfunctions`: 5 discoveries, 35 checks
  - `workflows`: 2 discoveries, 3 checks

## Implementation Details

### Changes Made

1. **YAML Consolidation** (`consolidate_services.py`)
   - Merged discovery and check sections from sub-services into main service YAMLs
   - Preserved service-specific rule IDs (e.g., `aws.eip.*`, `aws.vpc.*`)

2. **Engine Updates** (`engine/service_scanner.py`)
   - Updated `load_service_rules()` to handle consolidated services
   - When a sub-service is requested (e.g., `eip`, `vpc`), the engine:
     - Loads the main service YAML (e.g., `ec2.yaml`)
     - Filters rules by service prefix (e.g., `aws.eip.*`)
     - Returns only relevant rules for that service

### How It Works

When the engine requests rules for a consolidated service:

```python
# Request: load_service_rules('eip')
# 1. Detects 'eip' is consolidated → main service is 'ec2'
# 2. Loads services/ec2/rules/ec2.yaml
# 3. Filters to only rules with prefix 'aws.eip.'
# 4. Returns filtered rules with service: 'eip'
```

### Service Name Mapping

The consolidation mapping is defined in `engine/service_scanner.py`:

```python
CONSOLIDATED_SERVICES = {
    'eip': 'ec2',
    'vpc': 'ec2',
    'vpcflowlogs': 'ec2',
    'fargate': 'ecs',
    'kinesisfirehose': 'firehose',
    'parameterstore': 'ssm',
    'workflows': 'stepfunctions',
}
```

## Benefits

1. **Single Source of Truth**: All rules for a boto3 client are in one file
2. **Easier Maintenance**: Update once, affects all related services
3. **Cleaner Structure**: Reduces duplicate client initialization
4. **Backward Compatible**: Engine still works with individual service names

## Old Files

The original sub-service YAML files still exist in their folders:
- `services/eip/rules/eip.yaml`
- `services/vpc/rules/vpc.yaml`
- `services/vpcflowlogs/rules/vpcflowlogs.yaml`
- etc.

These are now redundant but kept for reference. They can be removed if desired.

## Testing

Verified that consolidated services load correctly:
- ✅ `eip` → loads from `ec2.yaml`, filters to `aws.eip.*` rules
- ✅ `vpc` → loads from `ec2.yaml`, filters to `aws.vpc.*` rules
- ✅ `vpcflowlogs` → loads from `ec2.yaml`, filters to `aws.vpcflowlogs.*` rules
- ✅ `fargate` → loads from `ecs.yaml`, filters to `aws.fargate.*` rules
- ✅ All other consolidated services working correctly
