---
story_id: AZ-04
title: Implement AzureDiscoveryScanner (DB-Driven)
status: done
sprint: azure-track-wave-4
depends_on: [AZ-02, AZ-02b, AZ-03, AZ-01b]
blocks: [AZ-05, AZ-12]
sme: Python/azure-mgmt-* engineer
estimate: 2 days
---

# Story: Implement AzureDiscoveryScanner (DB-Driven)

## Context
The main Azure scanner class that drives all resource discovery. Unlike the removed stub (AZ-01b), this scanner reads service configs from the `rule_discoveries` DB table — same as AWS. Each service-region pair runs in a ThreadPoolExecutor thread with a 10s timeout (AZ-02b).

**Critical requirement:** Use server-side region filtering where Azure SDK supports it. Do NOT fetch all resources in a subscription and then filter by location in Python — that's O(N) client-side.

## Files to Modify

- `engines/discoveries/providers/azure/scanner/service_scanner.py` — full implementation

## Implementation Notes

**Core scan flow:**
```python
class AzureDiscoveryScanner(DiscoveryScanner):
    def scan(self, regions: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        # 1. Load service configs from rule_discoveries WHERE provider='azure' AND is_enabled=true
        # 2. Get resource groups (needed for some Azure list methods)
        # 3. For each service × region: submit to ThreadPoolExecutor
        # 4. Collect results with _call_with_timeout (AZ-02b)
        # 5. Normalize each resource → standard dict with required fields
        # 6. Return flat list
```

**Server-side filtering (critical):**
- `compute`: `client.virtual_machines.list_all()` returns ALL VMs in subscription. Then filter by `vm.location`. This IS O(N) but Azure doesn't support location filter on `list_all`. Document this explicitly with a comment. Use `list_by_resource_group(rg)` where resource groups are pre-filtered by region.
- `storage`: `client.storage_accounts.list()` → filter by `account.location`
- `sql`: `client.servers.list()` → filter by `server.location`
- For services that truly support server-side filter, use it. Document which don't.

**resource_type normalization:**
```python
_RESOURCE_TYPE_MAP = {
    "Microsoft.Compute/virtualMachines":          "VirtualMachine",
    "Microsoft.Compute/virtualMachineScaleSets":  "VMSS",
    "Microsoft.Network/virtualNetworks":          "VirtualNetwork",
    "Microsoft.Network/networkSecurityGroups":    "NetworkSecurityGroup",
    "Microsoft.Network/loadBalancers":            "LoadBalancer",
    "Microsoft.Network/applicationGateways":      "ApplicationGateway",
    "Microsoft.Network/subnets":                  "Subnet",
    "Microsoft.Storage/storageAccounts":          "StorageAccount",
    "Microsoft.KeyVault/vaults":                  "KeyVault",
    "Microsoft.Sql/servers":                      "SQLServer",
    "Microsoft.ContainerService/managedClusters": "AKSCluster",
    "Microsoft.Web/sites":                        "AppService",
    "Microsoft.DocumentDB/databaseAccounts":      "CosmosDB",
    "Microsoft.Compute/disks":                    "ManagedDisk",
    # ... add more as needed
}
```

**Standard output dict per resource:**
```python
{
    "resource_uid":   full_azure_resource_id,   # /subscriptions/{sub}/resourceGroups/{rg}/providers/{type}/{name}
    "resource_type":  normalized_type,           # VirtualMachine, StorageAccount, etc.
    "resource_name":  resource.name,
    "provider":       "azure",
    "region":         resource.location,         # eastus, westeurope, etc.
    "account_id":     subscription_id,
    "raw_data":       resource.as_dict(),        # full Azure response for downstream check engine
}
```

## Reference Files
- AWS scanner (pattern to mirror): `engines/discoveries/providers/aws/scanner/service_scanner.py`
- DB load pattern: look for `load_discovery_configs` or similar in AWS scanner
- Timeout wrapper (AZ-02b): `_call_with_timeout()` in same file
- Pagination helper (AZ-03): `azure_list_all()` in `pagination.py`

## Acceptance Criteria
- [ ] Scanner loads services from `rule_discoveries` table (not hardcoded list)
- [ ] Each API call uses `_call_with_timeout(future, timeout=OPERATION_TIMEOUT)`
- [ ] All resources have `resource_uid` matching `/subscriptions/{sub}/resourceGroups/.+` format
- [ ] All resources have `provider: "azure"` in output dict
- [ ] Resource type is normalized (no `Microsoft.Compute/virtualMachines` in output — must be `VirtualMachine`)
- [ ] Server-side vs client-side filter documented per service with inline comments
- [ ] Unit test: mock DB returns 3 services, mock clients return 5 resources each → scanner returns 15 resources

## Definition of Done
- [ ] Full implementation with all required output fields
- [ ] Normalization map has >= 14 resource types
- [ ] Unit tests pass with mocked Azure SDK clients
- [ ] Code reviewed by architect (verify no O(N) hidden in tight loops)
- [ ] No hardcoded service names — all from DB