# YAML Rule Builder - Usage Guide

## Quick Start

```bash
cd yaml-rule-builder
python3 run.py <command> [options]
```

## Commands

### 1. List Services

List all available AWS services:

```bash
python3 run.py list-services
```

### 2. List Fields

List all available fields for a service:

```bash
python3 run.py list-fields --service accessanalyzer
```

### 3. Generate YAML (Interactive)

Interactive mode to build rules step-by-step:

```bash
python3 run.py generate --service accessanalyzer
```

This will:
1. Show available fields
2. Let you select field + operator + value
3. Check for existing rules
4. Collect metadata (title, description, remediation)
5. Generate YAML and metadata files

### 4. Generate YAML (from JSON)

Create a JSON file with your rules:

```json
[
  {
    "field_name": "status",
    "operator": "equals",
    "value": "ACTIVE",
    "rule_id": "aws.accessanalyzer.resource.analyzer_active",
    "title": "Analyzer Active",
    "description": "Check if analyzer is active",
    "remediation": "Enable the analyzer in AWS console"
  }
]
```

Then run:

```bash
python3 run.py generate --service accessanalyzer --input rules.json
```

## Features

- ✅ **Rule Comparison**: Automatically detects if a rule already exists
- ✅ **Metadata Generation**: Creates metadata YAML for custom rules
- ✅ **Custom Marking**: Marks user-created rules with `custom: true`
- ✅ **Dependency Resolution**: Automatically resolves operation dependencies

## Output

- **YAML File**: `aws_compliance_python_engine/services/{service}/rules/{service}.yaml`
- **Metadata File**: `aws_compliance_python_engine/services/{service}/metadata/{rule_id}.yaml`

