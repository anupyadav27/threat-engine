# YAML Rule Builder

A modular CLI tool for generating AWS compliance rule YAML files with automatic rule comparison and metadata generation.

## Core Concept

For each rule, you select **three things together**:
1. **Field** - The field to check (e.g., `status`)
2. **Operator** - How to check it (e.g., `equals`, `exists`, `greater_than`)
3. **Expected Value** - What value to expect (e.g., `ACTIVE`, `null`, `100`)

## Features

- ✅ **Rule Comparison**: Automatically detects existing rules with same field + operator + value
- ✅ **Metadata Generation**: Creates metadata YAML files for new custom rules
- ✅ **Custom Marking**: Marks user-created rules with `custom: true` field
- ✅ **Interactive Mode**: Step-by-step rule building with validation
- ✅ **JSON Input**: Batch processing from JSON files
- ✅ **Dependency Resolution**: Automatically resolves operation dependencies

## Installation

```bash
cd yaml-rule-builder
pip install -r requirements.txt
```

## Usage

### List Available Services

```bash
python -m yaml_rule_builder list-services
```

### List Fields for a Service

```bash
python -m yaml_rule_builder list-fields --service accessanalyzer
```

### Generate YAML Interactively

This will guide you through selecting Field + Operator + Value for each rule:

```bash
python -m yaml_rule_builder generate --service accessanalyzer
```

Example interactive session:
```
STEP 1: Select Field
  1. status
  2. name
  3. type
  ...

STEP 2: Select Operator for field 'status'
  1. equals
  2. not_equals
  3. in
  ...

STEP 3: Enter Expected Value
  Field: status
  Operator: equals
  Possible values:
    1. ACTIVE
    2. CREATING
    3. DISABLED
  ...

STEP 4: Checking for existing rules...
  ⚠️  EXISTING RULE FOUND!
     Rule ID: aws.accessanalyzer.resource.access_analyzer_enabled
     Source: .../accessanalyzer.yaml
  Use existing rule? (y/n): y

STEP 5: Rule Details (for new rules)
STEP 6: Rule Metadata (title, description, remediation)
```

### Generate YAML from JSON

Create a JSON file with field selections (Field + Operator + Value):

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
python -m yaml_rule_builder generate --service accessanalyzer --input rules.json --output accessanalyzer.yaml
```

## JSON Format

Each rule requires:
- `field_name`: The field to check
- `operator`: The operator to use (must be valid for the field)
- `value`: The expected value (null for `exists` operator)
- `rule_id`: Unique rule identifier
- `title`: Rule title (optional, for metadata)
- `description`: Rule description (optional, for metadata)
- `remediation`: Remediation steps (optional, for metadata)

## Architecture

```
yaml-rule-builder/
├── core/              # Core functionality
│   ├── data_loader.py
│   ├── dependency_resolver.py
│   ├── field_mapper.py
│   ├── yaml_generator.py
│   ├── rule_comparator.py
│   └── metadata_generator.py
├── models/            # Data models
│   ├── field_selection.py
│   └── discovery_chain.py
├── commands/          # CLI commands
│   ├── list_services.py
│   └── list_fields.py
├── utils/             # Utilities
│   └── validators.py
├── cli.py             # Main CLI entry point
└── config.py          # Configuration
```

## How It Works

1. **Field Selection**: User selects a field from available fields
2. **Operator Selection**: User selects a valid operator for that field
3. **Value Input**: User enters/selects expected value
4. **Rule Comparison**: Tool checks if identical rule exists (by for_each + var + op + value)
5. **Metadata Generation**: For new rules, creates metadata YAML with custom marking
6. **YAML Generation**: Generates complete YAML with discovery and checks sections

## Output

The tool generates:
- **YAML File**: `services/{service}/rules/{service}.yaml` with discovery and checks
- **Metadata File**: `services/{service}/metadata/{rule_id}.yaml` for custom rules

Metadata files include:
- `custom: true` - Marks as user-created
- `source: user_created` - Source identifier
- `created_at` - Timestamp
- `created_by: yaml_rule_builder` - Tool identifier

## Next Steps

1. Add support for multi-field conditions (all/any)
2. Add rule templates
3. Add validation against existing YAML files
4. Add export to metadata_mapping.json format

