---
story_id: AZ-01
title: Bootstrap Azure Provider Directory
status: done
sprint: azure-track-wave-1
depends_on: []
blocks: [AZ-02, AZ-12]
sme: Python/azure-mgmt-* engineer
estimate: 0.5 days
---

# Story: Bootstrap Azure Provider Directory

## Context
The discovery engine loads CSP-specific scanners via `PROVIDER_SCANNERS` registry in `run_scan.py`. AWS is the only live provider. Azure requires a provider directory under `engines/discoveries/providers/azure/` that follows the same structure as `engines/discoveries/providers/aws/`.

An existing stub at `engines/discoveries/providers/azure/scanner/service_scanner.py` (343 lines, 4 hardcoded handlers) exists but must NOT be used — it bypasses the DB-driven discovery model. This story creates the correct skeleton; AZ-01b removes the stub.

## Files to Create

```
engines/discoveries/providers/azure/
├── __init__.py                          # empty, marks as package
├── scanner/
│   ├── __init__.py                      # empty
│   └── service_scanner.py              # AzureDiscoveryScanner class (skeleton only — impl in AZ-04)
├── client_factory.py                    # AzureClientFactory (impl in AZ-02)
├── pagination.py                        # azure_list_all() helper (impl in AZ-03)
└── requirements.txt                     # azure-mgmt-* packages
```

## Implementation Notes

**`service_scanner.py` skeleton:**
```python
from typing import List, Dict, Any, Optional
from engines.discoveries.providers.base import DiscoveryScanner

class AzureDiscoveryScanner(DiscoveryScanner):
    """Azure cloud resource discovery scanner.
    
    Implements DB-driven service discovery for Azure subscriptions.
    All service enumeration is driven by rule_discoveries table, not hardcoded.
    """
    
    def __init__(self, credential_ref: str, credential_type: str,
                 tenant_id: str, account_id: str, scan_run_id: str) -> None:
        """Initialize Azure scanner with credentials from Secrets Manager."""
        pass
    
    def scan(self, regions: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Run full Azure discovery scan. Returns list of resource dicts."""
        pass
```

**`requirements.txt` contents:**
```
azure-mgmt-compute>=30.0.0
azure-mgmt-network>=25.0.0
azure-mgmt-storage>=21.0.0
azure-mgmt-keyvault>=10.0.0
azure-mgmt-sql>=3.0.0
azure-mgmt-authorization>=4.0.0
azure-mgmt-containerservice>=28.0.0
azure-mgmt-web>=7.0.0
azure-mgmt-monitor>=6.0.0
azure-mgmt-security>=5.0.0
azure-mgmt-resource>=23.0.0
azure-mgmt-cosmosdb>=9.0.0
azure-mgmt-dns>=8.0.0
azure-identity>=1.15.0
msgraph-sdk>=1.0.0
```

## Reference Files
- [AWS provider structure](engines/discoveries/providers/aws/) — mirror this layout
- [Base scanner interface](engines/discoveries/providers/base.py) — must implement this

## Acceptance Criteria
- [ ] `engines/discoveries/providers/azure/__init__.py` exists
- [ ] `AzureDiscoveryScanner` class importable: `from engines.discoveries.providers.azure.scanner.service_scanner import AzureDiscoveryScanner` — no ImportError
- [ ] `requirements.txt` contains all azure-mgmt-* packages listed above
- [ ] Class inherits from `DiscoveryScanner` base

## Definition of Done
- [ ] All files created, no syntax errors (`python -m py_compile` passes)
- [ ] Package import works in a clean Python 3.11 environment
- [ ] No stub/hardcoded handler code in this skeleton (that's AZ-01b to remove)