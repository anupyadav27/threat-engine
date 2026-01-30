# Rule DB Services Split Summary

## Overview
All service YAML files in `rule_db/default/services/` have been split into:
- **Main file**: `{service}.yaml` - Contains only discoveries
- **Checks file**: `{service}.checks.yaml` - Contains only checks

## Script
- **Location**: `split_rule_db_services.py`
- **Usage**: `python3 split_rule_db_services.py`

## Process
1. Scans all services in `default/services/` directory
2. For each service:
   - Reads main YAML file (`{service}.yaml`)
   - Removes `checks` section from main file
   - Creates new `{service}.checks.yaml` with only checks
   - Creates backup of original file (`.yaml.backup`)

## File Structure
```
services/
├── {service}/
│   └── rules/
│       ├── {service}.yaml          # Discoveries only
│       ├── {service}.checks.yaml   # Checks only
│       └── {service}.yaml.backup    # Original backup
```

## Benefits
1. **Separation of Concerns**: Discoveries and checks are decoupled
2. **Easier Maintenance**: Update checks without touching discoveries
3. **Flexibility**: Can have different check sources (default, custom)
4. **Database Integration**: Matches the two-phase architecture

## Validation
Run the script again to verify - it will show "already split" for services that have been processed.

