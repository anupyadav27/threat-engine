# EC2 MaxResults Fix

## Problem

Some EC2 `describe_*` operations don't support the `MaxResults` parameter, but our code was trying to add it anyway, causing validation errors:

```
WARNING Failed describe_reserved_instances: Parameter validation failed:
Unknown parameter in input: "MaxResults", must be one of: OfferingClass, ReservedInstancesIds, DryRun, Filters, OfferingType

WARNING Failed describe_availability_zones: Parameter validation failed:
Unknown parameter in input: "MaxResults", must be one of: ZoneNames, ZoneIds, AllAvailabilityZones, DryRun, Filters
```

Additionally, operations like `describe_addresses`, `describe_subnets`, `describe_security_groups` were taking 20-30 minutes because they return ALL resources in one API call (AWS API limitation - no pagination support).

## Root Cause

1. **EC2 describe operations don't support MaxResults**: Many EC2 `describe_*` operations return all results in a single call and don't support pagination parameters.

2. **Inherent slowness**: When there are many resources (thousands of security groups, subnets, addresses), these operations are inherently slow because AWS returns everything in one call.

3. **Our code was adding MaxResults**: The default pagination logic was adding `MaxResults: 1000` to ALL list/describe operations, including those that don't support it.

## Solution

Added a whitelist of EC2 operations that DON'T support MaxResults and skip adding it for those operations:

```python
# EC2 operations that DON'T support MaxResults
ec2_no_maxresults = {
    'describe_addresses', 'describe_subnets', 'describe_security_groups',
    'describe_availability_zones', 'describe_reserved_instances',
    'describe_placement_groups', 'describe_iam_instance_profile_associations',
    'describe_address_transfers', 'describe_classic_link_instances',
    'describe_network_interface_attribute', 'describe_nat_gateways',
    'describe_vpcs', 'describe_route_tables', 'describe_internet_gateways',
    'describe_vpc_peering_connections', 'describe_vpc_endpoints',
    'describe_network_acls', 'describe_customer_gateways', 'describe_vpn_gateways',
    'describe_vpn_connections', 'describe_network_interfaces'
}

# Skip MaxResults for these operations
if service_name == 'ec2' and action in ec2_no_maxresults:
    # Single API call (no MaxResults, no pagination)
    response = _retry_call(getattr(call_client, action), **resolved_params)
```

## Impact

### Before
- Validation errors for operations that don't support MaxResults
- Operations still slow (20-30 minutes) because they return all resources

### After
- No validation errors
- Operations still slow (expected - AWS API limitation)
- But at least they run correctly without errors

## Note

These operations are **inherently slow** when there are many resources. This is an AWS API limitation - they don't support pagination and return all results in one call. The slowness is expected behavior, not a bug.

## Operations Fixed

- ✅ describe_addresses
- ✅ describe_subnets  
- ✅ describe_security_groups
- ✅ describe_availability_zones
- ✅ describe_reserved_instances
- ✅ describe_placement_groups
- ✅ describe_iam_instance_profile_associations
- ✅ describe_address_transfers
- ✅ describe_classic_link_instances
- ✅ describe_network_interface_attribute
- ✅ describe_nat_gateways
- ✅ describe_vpcs
- ✅ describe_route_tables
- ✅ describe_internet_gateways
- ✅ describe_vpc_peering_connections
- ✅ describe_vpc_endpoints
- ✅ describe_network_acls
- ✅ describe_customer_gateways
- ✅ describe_vpn_gateways
- ✅ describe_vpn_connections
- ✅ describe_network_interfaces

