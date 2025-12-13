# Azure Agentic AI Pipeline for Rule Generation & Validation

## Overview

This pipeline generates and validates Azure compliance rule requirements using AI and Azure SDK analysis.
Similar to the AWS version but adapted for Azure SDK structure and naming conventions.

## The Flow

```
Metadata YAML (descriptions)
  ↓
Agent 1: AI Requirements Generator
  ↓
requirements_initial.json
  ↓
Agent 2: Function Name Validator (uses Azure SDK catalog)
  ↓
requirements_with_functions.json
  ↓
Agent 3: Field Name Validator (uses Azure SDK catalog)
  ↓
requirements_validated.json ← SINGLE SOURCE OF TRUTH
  ↓
Agent 4: YAML Generator
  ↓
{service}_generated.yaml
  ↓
Agent 5: Engine Tester
  ↓
engine_test_results.json
  ↓
Agent 6: Error Analyzer
  ↓
Agent 7: Auto Corrector
  ↓
Final Production-Ready YAML
```

## Agents

### Agent 1: Requirements Generator
- Reads Azure metadata YAML descriptions
- Uses Claude AI to interpret requirements
- Generates technical specifications (fields, operators, values)
- Understands Azure resource structure and naming
- Output: What each rule SHOULD check

### Agent 2: Function Validator
- Takes AI-generated requirements
- Finds Azure SDK operations that provide needed fields
- Validates operation names exist in Azure SDK catalog
- Corrects typos automatically (list_vm → list_virtual_machines)
- Maps to correct operations class (e.g., VirtualMachinesOperations)
- Output: Which Azure SDK operation to use for each rule

### Agent 3: Field Validator
- Takes requirements with validated functions
- Checks if fields exist in operation output
- Corrects case mismatches (Id → id, Name → name)
- Handles Azure-specific field patterns (properties.*, tags, location)
- Identifies computed fields (provisioning_state, etc.)
- Output: Fully validated requirements

### Agent 4: YAML Generator
- Converts validated requirements to YAML format
- Generates discovery sections (for_each: azure.service.list_*)
- Creates condition blocks with proper Azure field paths
- Handles Azure resource hierarchies (subscription/resource_group/resource)
- Output: Production-ready YAML rules

### Agent 5: Engine Tester
- Runs generated YAMLs through the Azure compliance engine
- Uses mock Azure resources or actual Azure subscriptions
- Validates YAML syntax and execution
- Reports errors and warnings
- Output: Test results with pass/fail status

### Agent 6: Error Analyzer
- Analyzes failed tests from Agent 5
- Categorizes errors (syntax, field not found, logic errors)
- Provides specific fix recommendations
- Identifies patterns in failures
- Output: Categorized error report

### Agent 7: Auto Corrector
- Automatically fixes common errors
- Corrects field paths based on Azure SDK structure
- Adjusts operators and values
- Regenerates YAML with fixes
- Re-runs tests to verify fixes
- Output: Auto-corrected YAML files

## Setup

### Prerequisites

```bash
# Install Azure SDK packages
pip install azure-mgmt-compute azure-mgmt-network azure-mgmt-storage
pip install azure-mgmt-keyvault azure-mgmt-sql azure-mgmt-web
pip install azure-identity anthropic

# Set API key
export ANTHROPIC_API_KEY='your-anthropic-api-key'

# Set Azure credentials (optional, for testing)
export AZURE_SUBSCRIPTION_ID='your-subscription-id'
export AZURE_TENANT_ID='your-tenant-id'
export AZURE_CLIENT_ID='your-client-id'
export AZURE_CLIENT_SECRET='your-client-secret'
```

### Verify Setup

```bash
# Ensure Azure SDK catalog exists
ls Agent-ruleid-rule-yaml/azure_sdk_dependencies_with_python_names.json

# Test analyzer
python3 Agent-ruleid-rule-yaml/azure_sdk_dependency_analyzer.py
```

## Usage

### Run Complete Pipeline

```bash
cd azure_compliance_python_engine
bash Agent-ruleid-rule-yaml/run_all_agents.sh
```

### Run Individual Agents

```bash
# Agent 1: Generate requirements from metadata
python3 Agent-ruleid-rule-yaml/agent1_requirements_generator.py

# Agent 2: Validate Azure SDK operations
python3 Agent-ruleid-rule-yaml/agent2_function_validator.py

# Agent 3: Validate fields
python3 Agent-ruleid-rule-yaml/agent3_field_validator.py

# Agent 4: Generate YAML
python3 Agent-ruleid-rule-yaml/agent4_yaml_generator.py

# Agent 5: Test with engine
python3 Agent-ruleid-rule-yaml/agent5_engine_tester.py

# Agent 6: Analyze errors
python3 Agent-ruleid-rule-yaml/agent6_error_analyzer.py

# Agent 7: Auto-correct
python3 Agent-ruleid-rule-yaml/agent7_auto_corrector.py
```

## Output Files

### Final File: `Agent-ruleid-rule-yaml/output/requirements_validated.json`

Example:
```json
{
  "compute": [
    {
      "rule_id": "azure.compute.vm.disk_encryption_enabled",
      "service": "compute",
      "description": "Ensures VM disk encryption is enabled...",
      "ai_generated_requirements": {
        "fields": [
          {
            "name": "properties.storageProfile.osDisk.encryptionSettings.enabled",
            "operator": "equals",
            "value": true
          }
        ],
        "condition_logic": "single"
      },
      "validated_function": {
        "python_method": "list",
        "azure_operation": "list",
        "operations_class": "VirtualMachinesOperations",
        "is_independent": true,
        "available_fields": [
          "id", "name", "type", "location", "tags",
          "properties", "identity", "zones", "..."
        ],
        "main_output_field": "value"
      },
      "field_validation": {
        "properties.storageProfile.osDisk.encryptionSettings.enabled": {
          "exists": true,
          "correct_name": "properties.storageProfile.osDisk.encryptionSettings.enabled",
          "validation": "nested_field",
          "path_valid": true
        }
      },
      "all_fields_valid": true,
      "final_validation_status": "✅ PASS"
    }
  ]
}
```

## Services Processed

Initial batch (5 services):
1. **compute** - VMs, Disks, Availability Sets (~40 rules)
2. **network** - VNets, NSGs, Load Balancers (~60 rules)
3. **storage** - Storage Accounts, Containers (~30 rules)
4. **keyvault** - Key Vaults, Keys, Secrets (~25 rules)
5. **sql** - SQL Servers, Databases (~35 rules)

Total: ~190 rules

## Azure-Specific Considerations

### Naming Conventions
- **AWS:** PascalCase operations (ListBuckets)
- **Azure:** snake_case operations (list_storage_accounts)

### Resource Structure
- **AWS:** Flat resource model
- **Azure:** Hierarchical (subscription → resource_group → resource)

### Field Paths
- **AWS:** Direct fields (Status, State)
- **Azure:** Nested properties (properties.provisioningState, properties.encryption.enabled)

### Common Azure Patterns
```yaml
# List all resources in subscription
for_each: azure.compute.list_virtual_machines

# Access nested properties
var: item.properties.storageProfile.osDisk.encryptionSettings.enabled

# Check tags
var: item.tags.Environment

# Check location
var: item.location
```

## Next Steps

Once you have `requirements_validated.json`:

1. **Generate YAML** ✅ - Use Agent 4
2. **Test with Engine** ✅ - Use Agent 5
3. **Fix Errors** ✅ - Use Agents 6 & 7
4. **Deploy to Production** - Copy validated YAMLs to services/

## Benefits

- 🤖 AI-powered requirement generation
- ✅ 100% validation against Azure SDK
- 🔄 Automatic error detection and correction
- 📊 Comprehensive testing before deployment
- 🚀 Scalable to all 23+ Azure services
- 📝 Single source of truth for all rules

## Scaling

### Process More Services

Edit `agent1_requirements_generator.py`:
```python
SERVICES_TO_PROCESS = [
    'compute',
    'network',
    'storage',
    'keyvault',
    'sql',
    'web',
    'monitor',
    'containerservice',
    # ... add more
]
```

### Process ALL Services
```python
import json
with open('azure_sdk_dependencies_with_python_names.json') as f:
    azure_data = json.load(f)

SERVICES_TO_PROCESS = list(azure_data.keys())  # All 23 services
```

## Comparison with AWS Pipeline

| Feature | AWS | Azure |
|---------|-----|-------|
| Services | 150+ | 23 |
| Operations | 40,000+ | 3,377 |
| Naming | PascalCase | snake_case |
| Structure | Flat | Hierarchical |
| Field Paths | Direct | Nested (properties.*) |
| Pagination | nextToken | value/next_link |

## Troubleshooting

### Common Issues

**Issue:** Field not found  
**Solution:** Check if field is nested (properties.fieldName)

**Issue:** Operation not found  
**Solution:** Use azure_sdk_dependency_analyzer.py to search

**Issue:** YAML syntax error  
**Solution:** Agent 6 will identify and Agent 7 will auto-fix

## Directory Structure

```
Agent-ruleid-rule-yaml/
├── agent_logger.py                              # Logging utility
├── azure_sdk_dependency_analyzer.py             # Azure SDK analyzer
├── azure_sdk_dependencies_with_python_names.json # Azure SDK catalog
├── agent1_requirements_generator.py             # AI requirements
├── agent2_function_validator.py                 # Validate operations
├── agent3_field_validator.py                    # Validate fields
├── agent4_yaml_generator.py                     # Generate YAML
├── agent5_engine_tester.py                      # Test engine
├── agent6_error_analyzer.py                     # Analyze errors
├── agent7_auto_corrector.py                     # Auto-fix
├── run_all_agents.sh                            # Run pipeline
├── README.md                                    # This file
├── output/
│   ├── requirements_initial.json
│   ├── requirements_with_functions.json
│   ├── requirements_validated.json             # FINAL
│   ├── {service}_generated.yaml
│   └── engine_test_results.json
└── logs/
    ├── pipeline.log
    └── agent{N}_{timestamp}.log
```

## Contributing

When adding new agents:
1. Use `agent_logger.py` for logging
2. Follow naming pattern: `agentN_description.py`
3. Update `run_all_agents.sh`
4. Document in README

## License

Internal use only - Threat Engine Compliance Framework

---

**Status:** 🚧 In Development  
**Last Updated:** December 12, 2024  
**Maintainer:** AI Compliance Team

