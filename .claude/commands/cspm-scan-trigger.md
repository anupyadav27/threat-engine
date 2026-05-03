# /cspm-scan-trigger

Trigger a CSPM scan via Argo Workflow.

## Usage
```
/cspm-scan-trigger <engine> <scan-run-id>
/cspm-scan-trigger all <scan-run-id>
```

Examples:
```
/cspm-scan-trigger network-security abc123-uuid
/cspm-scan-trigger all $(uuidgen)
```

## Trigger command
```bash
bash deployment/aws/eks/argo/trigger-scan.sh --engine <name> <scan-run-id>
```

## Engine name mapping for trigger-scan.sh

| Engine | trigger-scan.sh name |
|--------|---------------------|
| Discoveries | discoveries |
| Inventory | inventory |
| Check | check |
| Threat | threat |
| Compliance | compliance |
| IAM | iam |
| DataSec | datasec |
| Network Security | **network-security** (NOT network) |
| CIEM | ciem |
| Risk | risk |
| SecOps | secops |
| Vulnerability | vulnerability |

**Note:** Network engine trigger name is `network-security` (with hyphen), not `network`.

## Argo Workflow status
```bash
argo list -n argo
argo get <workflow-name> -n argo
argo logs <workflow-name> -n argo
```

## Pipeline requirements per engine
- discoveries: needs valid account_id + credentials in Secrets Manager
- inventory: requires discoveries to be complete
- check: requires discoveries to be complete
- threat: requires check + inventory to be complete
- compliance/iam/datasec/network: require threat to be complete
- risk: requires all Stage 5 engines to be complete
