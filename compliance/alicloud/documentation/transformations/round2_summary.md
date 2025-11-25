# Alicloud Service Naming Fix - Round 2

**Date:** 2025-11-19 13:17:15  
**Transformation Round:** 2  
**Total Rules Fixed:** 64

## Overview

This round fixed multi-word service patterns where compound service names appeared in the resource portion of rule IDs with underscores.

## Service Mappings

| Old Pattern | New Service | Description | Rules Fixed |
|-------------|-------------|-------------|-------------|
| `alibaba.cloud_config_*` | `config.*` | Config Service | 19 |
| `alibaba.cloud_cdn_*` | `cdn.*` | Content Delivery Network | 13 |
| `alibaba.cloud_dns_*` | `dns.*` | DNS Service | 12 |
| `cloud.firewall_*` | `cfw.*` | Cloud Firewall | 7 |
| `cloud.governance_center_*` | `governance.*` | Cloud Governance Center | 6 |
| `data.security_center_*` | `dsc.*` | Data Security Center | 5 |
| `cloud.assistant__oos_*` | `oos.*` | Operation Orchestration Service | 2 |

## Transformation Examples

### Data Security Center (DSC)
```
❌ OLD: alicloud.data.security_center_classification_data_governance_security_classification_auto_classification_enabled_where_supported
✅ NEW: alicloud.dsc.classification_data_governance_security_classification_auto_classification_enabled_where_supported
```

### Config Service
```
❌ OLD: alicloud.alibaba.cloud_config_recorder_configuration_management_security_config_recorder_enabled
✅ NEW: alicloud.config.recorder_configuration_management_security_config_recorder_enabled
```

### CDN Service
```
❌ OLD: alicloud.alibaba.cloud_cdn_dcdn_edge_security_cdn_access_logging_enabled
✅ NEW: alicloud.cdn.dcdn_edge_security_cdn_access_logging_enabled
```

### DNS Service
```
❌ OLD: alicloud.alibaba.cloud_dns_zone_dns_security_zone_dnssec_enabled_where_supported
✅ NEW: alicloud.dns.zone_dns_security_zone_dnssec_enabled_where_supported
```

### Cloud Firewall (CFW)
```
❌ OLD: alicloud.cloud.firewall_network_security_firewall_logging_enabled
✅ NEW: alicloud.cfw.network_security_firewall_logging_enabled
```

### Cloud Governance Center
```
❌ OLD: alicloud.cloud.governance_center_data_governance_security_compliance_access_rbac_least_privilege
✅ NEW: alicloud.governance.data_governance_security_compliance_access_rbac_least_privilege
```

### OOS (Operation Orchestration Service)
```
❌ OLD: alicloud.cloud.assistant__oos_vuln_security_maintenance_execution_roles_least_privilege
✅ NEW: alicloud.oos.vuln_security_maintenance_execution_roles_least_privilege
```

## Files Updated

- ✅ `compliance/consolidated_rules_phase4_2025-11-08_FINAL_ALICLOUD_CSPM_COMPLIANT.csv`
- ✅ `compliance/alicloud/rule_ids.yaml`

## Backups

Original files backed up to:
- `compliance/alicloud/backups/2025-11-19_service_naming_fix_round2/`

## Documentation Generated

1. `SERVICE_NAMING_TRANSFORMATION_ROUND2_MAP.json` - Full transformation mapping
2. `SERVICE_NAMING_TRANSFORMATION_ROUND2_CHANGELOG.json` - Detailed changelog
3. `SERVICE_NAMING_TRANSFORMATION_ROUND2_SUMMARY.md` - This document

## Validation

All transformations follow the pattern:
```
alicloud.{abbreviated_service}.{resource}_{check_name}
```

Where:
- Service names are properly abbreviated (dsc, cdn, config, dns, cfw, oos, governance)
- No underscores in service names
- Resources and checks use underscores for word separation
- Consistent dot notation throughout

## Status

✅ **COMPLETE** - All 64 rules successfully transformed
