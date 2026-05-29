# DI-S2-04 — asset_relationships Builder (All CSPs)
**Sprint**: DI-S2 | **Points**: 8 | **Status**: Ready for Dev

## Goal
Build the `asset_relationships` populator. Derive security-relevant relationships from
`asset_inventory.emitted_fields` JSONB across all 7 CSPs. These relationships replace
`inventory_relationships` for attack-path BFS, network topology, and threat-v1 graph edges.
Column names must be identical to `inventory_relationships` — zero logic changes in consumers.

## Context
The relationship builder runs as Phase 2b (after Phase 2a writes `asset_inventory`). It reads
newly written `asset_inventory` rows, extracts relationship fields from `emitted_fields`, and
writes `asset_relationships`. All existing consumers (attack-path `_ATTACK_RELEVANT_TYPES`,
network `inventory_reader.py`, threat-v1 `edge_builder.py`) use `relation_type` enum values —
these are unchanged.

## Files to Modify
- `engines/di/di_engine/phase2/relationship_writer.py` — full relationship builder
- `engines/di/run_scan.py` — call `run_phase2b()` after `run_phase2()`

## Relationship Types to Build (all CSPs)

### AWS
| from_resource_type | to_resource_type | relation_type | emitted_fields key |
|--------------------|------------------|---------------|--------------------|
| ec2.instance | ec2.subnet | PLACED_IN | SubnetId |
| ec2.instance | ec2.vpc | PLACED_IN | VpcId |
| ec2.instance | ec2.security_group | PROTECTED_BY | SecurityGroups[].GroupId |
| ec2.subnet | ec2.vpc | BELONGS_TO | VpcId |
| ec2.subnet | ec2.route_table | ROUTES_VIA | (RouteTableAssociation) |
| ec2.internet_gateway | ec2.vpc | ATTACHED_TO | Attachments[].VpcId |
| rds.db_instance | ec2.vpc | PLACED_IN | DBSubnetGroup.VpcId |
| rds.db_instance | ec2.security_group | PROTECTED_BY | VpcSecurityGroups[].VpcSecurityGroupId |
| lambda.function | ec2.subnet | PLACED_IN | VpcConfig.SubnetIds[] |
| lambda.function | ec2.vpc | PLACED_IN | VpcConfig.VpcId |
| eks.cluster | ec2.vpc | PLACED_IN | ResourcesVpcConfig.VpcId |
| elbv2.load_balancer | ec2.vpc | PLACED_IN | VpcId |
| elbv2.load_balancer | ec2.subnet | SPANS | AvailabilityZones[].SubnetId |
| elbv2.load_balancer | ec2.security_group | PROTECTED_BY | SecurityGroups[] |
| s3.bucket | (internet) | INTERNET_ACCESSIBLE | (if PublicAccessBlockConfiguration = off) |
| ec2.instance | (internet) | INTERNET_ACCESSIBLE | (if PublicIpAddress != null) |

### Azure
| from_resource_type | to_resource_type | relation_type | emitted_fields key |
|--------------------|------------------|---------------|--------------------|
| azure.vm | azure.vnet | PLACED_IN | networkProfile.networkInterfaces[].subnetId (extract vnet) |
| azure.vm | azure.nsg | PROTECTED_BY | networkProfile.networkInterfaces[].networkSecurityGroup.id |
| azure.sql_database | azure.vnet | PLACED_IN | virtualNetworkRules[].virtualNetworkSubnetId |

### GCP / OCI / IBM / AliCloud / K8s
Similar patterns — derive from `emitted_fields` keys for VPC/VNet references, SG references,
subnet references. Each CSP's relationship extractor runs only when provider matches.

## Implementation

### relationship_writer.py
```python
"""Phase 2b: Build asset_relationships from asset_inventory.emitted_fields."""
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger('di.phase2b')

# (from_resource_type, to_resource_type, relation_type, emitted_fields_path, to_uid_resolver)
# to_uid_resolver: function(value, from_row) → to_uid OR None if cannot resolve
RELATIONSHIP_RULES: List[Tuple] = [
    ('ec2.instance', 'ec2.subnet', 'PLACED_IN', 'SubnetId', _resolve_aws_subnet_uid),
    ('ec2.instance', 'ec2.vpc', 'PLACED_IN', 'VpcId', _resolve_aws_vpc_uid),
    ('ec2.instance', 'ec2.security_group', 'PROTECTED_BY',
     'SecurityGroups[].GroupId', _resolve_aws_sg_uid),
    ('ec2.subnet', 'ec2.vpc', 'BELONGS_TO', 'VpcId', _resolve_aws_vpc_uid),
    ('ec2.internet_gateway', 'ec2.vpc', 'ATTACHED_TO',
     'Attachments[].VpcId', _resolve_aws_vpc_uid),
    ('rds.db_instance', 'ec2.vpc', 'PLACED_IN',
     'DBSubnetGroup.VpcId', _resolve_aws_vpc_uid),
    ('rds.db_instance', 'ec2.security_group', 'PROTECTED_BY',
     'VpcSecurityGroups[].VpcSecurityGroupId', _resolve_aws_sg_uid),
    ('lambda.function', 'ec2.vpc', 'PLACED_IN', 'VpcConfig.VpcId', _resolve_aws_vpc_uid),
    ('elbv2.load_balancer', 'ec2.vpc', 'PLACED_IN', 'VpcId', _resolve_aws_vpc_uid),
    ('elbv2.load_balancer', 'ec2.security_group', 'PROTECTED_BY',
     'SecurityGroups[]', _resolve_aws_sg_uid),
    ('eks.cluster', 'ec2.vpc', 'PLACED_IN',
     'ResourcesVpcConfig.VpcId', _resolve_aws_vpc_uid),
]

# Internet-exposure virtual relationships
INTERNET_UID = 'pseudo:internet:global'

def run_phase2b(di_conn, scan_run_id: str, tenant_id: str) -> Dict[str, int]:
    """Build asset_relationships from asset_inventory rows for this scan.

    Reads from asset_inventory (already written by Phase 2a).
    Writes to asset_relationships.
    Returns stats: {written, skipped_no_target}
    """
    stats = {'written': 0, 'skipped_no_target': 0}
    rows = _load_inventory_rows(di_conn, scan_run_id, tenant_id)
    # Build UID lookup: resource_type+value → resource_uid
    uid_lookup = _build_uid_lookup(rows)

    relationships = []
    for row in rows:
        ef = row.get('emitted_fields') or {}
        from_uid = row['resource_uid']
        from_rtype = row['resource_type']

        for (from_rtype_rule, to_rtype, rel_type, ef_path, resolver) in RELATIONSHIP_RULES:
            if from_rtype != from_rtype_rule:
                continue
            values = _extract_path(ef, ef_path)
            if not values:
                continue
            for val in (values if isinstance(values, list) else [values]):
                to_uid = resolver(val, row, uid_lookup)
                if not to_uid:
                    stats['skipped_no_target'] += 1
                    continue
                relationships.append({
                    'scan_run_id': scan_run_id,
                    'tenant_id': tenant_id,
                    'from_uid': from_uid,
                    'to_uid': to_uid,
                    'relation_type': rel_type,
                    'from_resource_type': from_rtype,
                    'to_resource_type': to_rtype,
                    'properties': {},
                })

        # Internet exposure
        if _is_internet_exposed(row):
            relationships.append({
                'scan_run_id': scan_run_id,
                'tenant_id': tenant_id,
                'from_uid': from_uid,
                'to_uid': INTERNET_UID,
                'relation_type': 'INTERNET_ACCESSIBLE',
                'from_resource_type': from_rtype,
                'to_resource_type': 'internet',
                'properties': {},
            })

    _batch_write_relationships(di_conn, relationships, stats)
    logger.info("Phase 2b complete: %s", stats)
    return stats
```

## Acceptance Criteria

### Functional
- [ ] `asset_relationships` populated after Phase 2b for test AWS account
- [ ] EC2 instance → subnet, VPC, security_group relationships present
- [ ] Internet-facing EC2 instances (PublicIpAddress != null) → `INTERNET_ACCESSIBLE` relationship with `to_uid='pseudo:internet:global'`
- [ ] `asset_relationships` column names match `inventory_relationships` exactly (verified by schema diff)
- [ ] Attack-path BFS works with `asset_relationships` as source (tested in DI-S3-06)
- [ ] `relation_type` enum values unchanged: `PLACED_IN`, `BELONGS_TO`, `PROTECTED_BY`, `ATTACHED_TO`, `INTERNET_ACCESSIBLE`, `ROUTES_VIA`, `SPANS`, `CONTAINS`
- [ ] Azure, GCP, OCI relationships present for test accounts (at least 1 relationship type per CSP)

### Security
- [ ] `tenant_id` in all queries — no cross-tenant relationship writes
- [ ] `pseudo:internet:global` UID written as a known sentinel — attack-path BFS specifically checks for this node label

### Error Handling
- [ ] Missing target UID in `uid_lookup` → `stats.skipped_no_target += 1`, log DEBUG — not a crash
- [ ] Batch insert failure → rollback + continue with next batch

## Testing Requirements

**Unit** (`tests/engines/di/test_relationship_writer.py`):
- EC2 instance with SubnetId in emitted_fields → PLACED_IN relationship generated
- EC2 instance with PublicIpAddress → INTERNET_ACCESSIBLE generated
- EC2 instance without SubnetId → no PLACED_IN, `skipped_no_target` incremented
- `asset_relationships` column names match `inventory_relationships` column names (schema test)

**Integration**: After full DI scan, `SELECT count(*) FROM asset_relationships` > 0

## Review Gates
| Gate | Agent | Blocks |
|------|-------|--------|
| Pre-dev | bmad-sm | dev start |
| Security review | bmad-security-reviewer | merge |
| QA acceptance | cspm-qa | deploy |

## Definition of Done
- [ ] `relationship_writer.py` fully implemented with AWS + Azure + GCP rules
- [ ] Column names verified identical to `inventory_relationships`
- [ ] INTERNET_ACCESSIBLE relationships present for public-facing resources
- [ ] Unit + integration tests passing
- [ ] No cross-tenant relationship writes

## Dependencies
- DI-S1-05 (Phase 2a writer — `asset_inventory` must exist before 2b reads it)
- DI-S1-01 (`asset_relationships` table created)

## Rollback
```sql
DELETE FROM asset_relationships WHERE scan_run_id = '<bad_scan_run_id>';
```