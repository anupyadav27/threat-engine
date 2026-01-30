# Drift Threats

This document describes how configuration drift and check-status drift are detected and exposed by the Threat Engine.

## Drift Types

### 1. Configuration Drift
Detected from `discovery_history` records with `change_type = 'modified'`.

Signals:
- `diff_summary` indicates fields added/removed/modified.
- `config_hash` differs from `previous_hash`.

### 2. Check Status Drift
Detected by comparing two consecutive check scans:
- `PASS/WARN/ERROR` → `FAIL`
- `PASS` → `WARN`

## Data Sources

- `discoveries` and `discovery_history` tables (for configuration changes)
- `check_results` table (for check status changes)
- `rule_metadata` table (for rule severity metadata, used for check drift severity mapping)

## API Endpoint

### `GET /api/v1/threat/drift`

Query parameters:
- `tenant_id` (required)
- `account_id` (optional)
- `service` (optional)

Response:
```json
{
  "configuration_drift": [ ... ],
  "check_status_drift": [ ... ],
  "summary": {
    "total": 12,
    "by_severity": {
      "high": 5,
      "medium": 7
    },
    "by_type": {
      "configuration_drift": 8,
      "check_status_drift": 4
    }
  }
}
```

## Threat Report Integration

Drift threats are appended to the existing `threats` list during `/api/v1/threat/generate` and `/api/v1/threat/generate/from-ndjson`.

## Severity Mapping

### Configuration Drift
Severity is derived from changed fields:
- `high`: critical fields (policy, encryption, public access, versioning, kms)
- `medium`: more than 5 fields changed
- `low`: otherwise

### Check Status Drift
Severity uses `rule_metadata.severity` (if available), otherwise defaults to `medium`.
