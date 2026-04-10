---
story_id: AZ-08
title: Seed CIS Azure 1.5 Compliance Framework + Controls
status: done
sprint: azure-track-wave-3
depends_on: []
blocks: [AZ-11, AZ-13]
sme: Compliance / Backend
estimate: 1 day
---

# Story: Seed CIS Azure 1.5 Compliance Framework + Controls

## Context
The compliance engine currently has no Azure frameworks. The `compliance_frameworks` and
`compliance_controls` tables need CIS Azure Foundations Benchmark 1.5.0 data before
compliance scoring for Azure tenants is possible.

## Files to Create

- `consolidated_services/database/migrations/025_seed_cis_azure_framework.sql`

## Implementation Notes

### compliance_frameworks row:
```sql
INSERT INTO compliance_frameworks (framework_id, framework_name, version, description, authority, category, framework_data)
VALUES (
  'cis_azure_1_5',
  'CIS Microsoft Azure Foundations Benchmark',
  '1.5.0',
  'CIS security configuration best practices for Microsoft Azure',
  'Center for Internet Security',
  'cloud_security',
  '{"provider": "azure", "total_controls": 87}'::jsonb
)
ON CONFLICT (framework_id) DO UPDATE SET ...;
```

### compliance_controls rows — all 87 CIS Azure 1.5 controls:

| Section | Range | Count | Topic |
|---------|-------|-------|-------|
| 1 | 1.1–1.25 | 25 | Identity and Access Management |
| 2 | 2.1–2.15 | 15 | Microsoft Defender for Cloud |
| 3 | 3.1–3.15 | 15 | Storage Accounts |
| 4 | 4.1–4.9  | 9  | Database Services |
| 5 | 5.1–5.6  | 6  | Logging and Monitoring |
| 6 | 6.1–6.6  | 6  | Networking |
| 7 | 7.1–7.7  | 7  | Virtual Machines |
| 8 | 8.1–8.8  | 8  | App Service |
| 9 | 9.1–9.4  | 4  | Key Vault |

control_id format: `cis_azure_1_5_<section>_<number>` e.g., `cis_azure_1_5_1_1`

### Also add Azure Security Benchmark (optional):
```sql
INSERT INTO compliance_frameworks (framework_id, framework_name, version, ...)
VALUES ('azure_security_benchmark', 'Microsoft Azure Security Benchmark', '3.0', ...)
```

## Acceptance Criteria
- [ ] `SELECT count(*) FROM compliance_frameworks WHERE framework_id='cis_azure_1_5'` = 1
- [ ] `SELECT count(*) FROM compliance_controls WHERE framework_id='cis_azure_1_5'` >= 87
- [ ] Migration idempotent (re-run safe, ON CONFLICT DO UPDATE)
- [ ] Compliance engine can score against `cis_azure_1_5` once rules are mapped (AZ-11)

## Definition of Done
- [ ] Migration committed and applied
- [ ] Controls cover all 9 CIS sections