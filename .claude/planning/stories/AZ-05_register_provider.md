---
story_id: AZ-05
title: Register Azure Provider + Noise Removal
status: done
sprint: azure-track-wave-5
depends_on: [AZ-04]
blocks: [AZ-12]
sme: Backend engineer
estimate: 0.5 days
---

# Story: Register Azure Provider in run_scan.py + Noise Removal

## Context
`run_scan.py` is the entry point that maps `provider` parameter to the correct scanner class. Azure must be registered here. Additionally, several Azure services in `rule_discoveries` produce no security value (billing, audit logs, health) and should be disabled to reduce noise and scan time.

## Files to Modify

- `engines/discoveries/run_scan.py` — add Azure to PROVIDER_SCANNERS
- DB migration: `UPDATE rule_discoveries SET is_enabled=false WHERE provider='azure' AND service IN (...)`

## Implementation Notes

**run_scan.py change:**
```python
from engines.discoveries.providers.azure.scanner.service_scanner import AzureDiscoveryScanner

PROVIDER_SCANNERS = {
    "aws":   AWSDiscoveryScanner,
    "azure": AzureDiscoveryScanner,  # ADD THIS
    # "gcp": GCPDiscoveryScanner,   # future
    # "k8s": K8sDiscoveryScanner,   # future
}
```

**Noise removal SQL (run as one-time migration):**
```sql
UPDATE rule_discoveries
SET is_enabled = false,
    disabled_reason = 'non-security: billing/monitoring/health API'
WHERE provider = 'azure'
  AND service IN (
    'consumption',
    'costmanagement',
    'insights/metricDefinitions',
    'insights/activityLogs',
    'advisor',
    'resourcehealth',
    'maintenance',
    'locks'
  );
```

Save this SQL as: `consolidated_services/database/migrations/disable_azure_noise_services.sql`

## Reference Files
- `engines/discoveries/run_scan.py` — find existing PROVIDER_SCANNERS dict

## Acceptance Criteria
- [ ] `python engines/discoveries/run_scan.py --provider azure` starts without ImportError
- [ ] `PROVIDER_SCANNERS["azure"]` resolves to `AzureDiscoveryScanner`
- [ ] Migration SQL file exists at correct path
- [ ] `SELECT COUNT(*) FROM rule_discoveries WHERE provider='azure' AND is_enabled=false AND disabled_reason LIKE 'non-security%'` = 8 (the noise services)

## Definition of Done
- [ ] `run_scan.py` updated
- [ ] Migration SQL written and documented
- [ ] No regression: `--provider aws` still starts correctly