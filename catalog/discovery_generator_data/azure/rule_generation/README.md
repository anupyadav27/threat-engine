# Azure Check Rule Generation Framework

## Overview
This framework generates Azure security check rules using the same scope + assertion pattern as AWS.

## Structure
```
rule_generation/
├── README.md                           # This file
├── 01_security_domains.yaml            # 14 top-level security domains (same across CSPs)
├── 02_assertion_catalog.yaml           # Cross-CSP security assertions (reusable)
├── 03_azure_service_scopes.yaml        # Azure-specific service+resource scopes
├── 04_azure_scope_assertion_mapping.csv # Maps Azure scopes → assertions → fields
└── generate_azure_checks.py            # Generator script
```

## Flow
1. Security domains (CSP-agnostic) → define WHAT to check
2. Assertion catalog (CSP-agnostic) → define HOW to validate
3. Azure scopes (Azure-specific) → define WHERE to check (which discovery + field)
4. Mapping → combines scope + assertion + Azure field + operator + value
5. Generator → produces {service}.checks.yaml files
