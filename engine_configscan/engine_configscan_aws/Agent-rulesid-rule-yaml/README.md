# 3-Agent Pipeline for Requirements Generation & Validation

## Overview

This pipeline generates and validates compliance rule requirements using AI and boto3 analysis.

## The Flow

```
Metadata YAML (descriptions)
  ↓
Agent 1: AI Requirements Generator
  ↓
requirements_initial.json
  ↓
Agent 2: Function Name Validator (uses boto3 catalog)
  ↓
requirements_with_functions.json
  ↓
Agent 3: Field Name Validator (uses boto3 catalog)
  ↓
requirements_validated.json ← SINGLE SOURCE OF TRUTH
```

## Agents

### Agent 1: Requirements Generator
- Reads metadata YAML descriptions
- Uses Claude AI to interpret requirements
- Generates technical specifications (fields, operators, values)
- Output: What each rule SHOULD check

### Agent 2: Function Validator
- Takes AI-generated requirements
- Finds boto3 functions that provide needed fields
- Validates function names exist
- Corrects typos automatically
- Output: Which function to use for each rule

### Agent 3: Field Validator
- Takes requirements with validated functions
- Checks if fields exist in function output
- Corrects case mismatches (Status → status)
- Identifies computed fields
- Output: Fully validated requirements

## Setup

```bash
# Set API key
export ANTHROPIC_API_KEY='your-anthropic-api-key'

# Ensure boto3 catalog exists
ls framework/boto3_dependencies_with_python_names.json
```

## Usage

### Run Complete Pipeline
```bash
bash agents/run_all_agents.sh
```

### Run Individual Agents
```bash
# Agent 1
python3 agents/agent1_requirements_generator.py

# Agent 2
python3 agents/agent2_function_validator.py

# Agent 3
python3 agents/agent3_field_validator.py
```

## Output

### Final File: `agents/output/requirements_validated.json`

Example:
```json
{
  "accessanalyzer": [
    {
      "rule_id": "aws.accessanalyzer.resource.access_analyzer_enabled",
      "service": "accessanalyzer",
      "description": "Verifies security configuration...",
      "ai_generated_requirements": {
        "fields": [
          {"name": "status", "operator": "equals", "value": "ACTIVE"}
        ],
        "condition_logic": "single"
      },
      "validated_function": {
        "python_method": "list_analyzers",
        "boto3_operation": "ListAnalyzers",
        "is_independent": true,
        "available_fields": ["arn", "name", "status", "type", ...],
        "main_output_field": "analyzers"
      },
      "field_validation": {
        "status": {
          "exists": true,
          "correct_name": "status",
          "validation": "exact_match"
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
1. accessanalyzer - 2 rules
2. acm - 14 rules  
3. athena - ~10 rules
4. apigateway - ~30 rules
5. s3 - ~80 rules

Total: ~137 rules

## Next Steps

Once you have `requirements_validated.json`:

1. **Generate YAML** - Use validated requirements to create discovery + checks
2. **Generate Python** - Create compliance scripts from requirements
3. **Update Documentation** - Auto-generate docs from requirements
4. **Validate Existing** - Compare current YAML against validated requirements

## Benefits

- Single source of truth for all compliance rules
- AI-generated, boto3-validated requirements
- No guessing field names or function names
- 100% accuracy against AWS APIs
- Scalable to all services

## Scaling

To add more services:
1. Edit `agent1_requirements_generator.py`
2. Add service names to `SERVICES_TO_PROCESS` list
3. Re-run pipeline

To process ALL services:
```python
SERVICES_TO_PROCESS = list(boto3_data.keys())  # All 411 services
```
