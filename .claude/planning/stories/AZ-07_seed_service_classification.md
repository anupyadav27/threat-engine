---
story_id: AZ-07
title: Seed Azure service_classification (Inventory Asset Types)
status: done
sprint: azure-track-wave-3
depends_on: []
blocks: [AZ-13]
sme: Backend / DB
estimate: 0.5 days
---

# Story: Seed Azure service_classification

## Context
The `service_classification` table controls what appears in the Assets inventory tab per CSP.
It currently has only AWS entries. Azure scans will produce `VirtualMachine`, `StorageAccount`,
`SQLServer`, etc. as `resource_type` values — these need classification rows so the inventory
engine can categorise, label, and display them correctly.

**CONFLICT key:** `(csp, resource_type)` — safe to re-run.

## Files to Create

- `consolidated_services/database/migrations/024_seed_azure_service_classification.sql`

## Implementation Notes

Target table columns needed:
`csp, resource_type, service, resource_name, display_name, scope, category, subcategory,
service_model, managed_by, access_pattern, is_container, container_parent, diagram_priority, csp_category`

14 resource types to seed (from 14_AZURE_E2E_PLAN.md §Milestone 2.2):
VirtualMachine, StorageAccount, SQLServer, KeyVault, VirtualNetwork, NetworkSecurityGroup,
AppService, AKSCluster, CosmosDB, LoadBalancer, ApplicationGateway, Subnet, ManagedDisk, ContainerRegistry

## Acceptance Criteria
- [ ] `SELECT count(*) FROM service_classification WHERE csp='azure'` returns 14
- [ ] Migration re-runnable without errors (ON CONFLICT DO UPDATE)
- [ ] Each row has non-null category, subcategory, scope

## Definition of Done
- [ ] Migration file committed
- [ ] Applied to RDS (verify row count)