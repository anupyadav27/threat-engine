---
story_id: AZ-01b
title: Remove Existing Azure Scanner Stub
status: done
sprint: azure-track-wave-1
depends_on: []
blocks: [AZ-04]
sme: Python/azure-mgmt-* engineer
estimate: 0.5 hours
---

# Story: Remove Existing Azure Scanner Stub

## Context
`engines/discoveries/providers/azure/scanner/service_scanner.py` currently contains a 343-line stub with 4 hardcoded service handlers (`compute`, `sql`, `storage`, `resource_groups`). This bypasses the DB-driven discovery model (rule_discoveries table) that all other providers use.

If this stub is not removed before AZ-04 is merged, the old hardcoded handlers could shadow the new DB-driven scanner and produce partial, unreliable results with no error.

## Files to Modify

- `engines/discoveries/providers/azure/scanner/service_scanner.py` — replace stub content with the AZ-01 skeleton class (or leave as skeleton pending AZ-04)

## Implementation Notes

The stub has a `@azure_handler("compute")` decorator registry pattern. This entire registry should be removed. The new pattern (from AZ-04) will use the DB `rule_discoveries` table to enumerate services, same as AWS.

Steps:
1. Read the existing stub to catalog what hardcoded handlers exist
2. Replace file content with the AzureDiscoveryScanner skeleton from AZ-01
3. Confirm no other file imports from the stub's `@azure_handler` registry

## Reference Files
- Existing stub: `engines/discoveries/providers/azure/scanner/service_scanner.py`
- AWS DB-driven pattern: `engines/discoveries/providers/aws/scanner/service_scanner.py`

## Acceptance Criteria
- [ ] No `@azure_handler` decorator or handler registry exists in the file
- [ ] No hardcoded service names (`compute`, `sql`, `storage`, `resource_groups`) remain as handler registrations
- [ ] `grep -r "azure_handler" engines/discoveries/providers/azure/` returns no matches
- [ ] `AzureDiscoveryScanner` class still importable after change

## Definition of Done
- [ ] File contains only the skeleton class from AZ-01 (or the full implementation from AZ-04 if done after)
- [ ] No regression: existing imports in run_scan.py still resolve