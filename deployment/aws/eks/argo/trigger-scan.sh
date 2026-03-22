#!/bin/bash
# Trigger a CSPM scan via Argo Workflows
#
# Usage:
#   Full pipeline:     bash trigger-scan.sh <scan-run-id> <tenant-id> <account-id> [provider]
#   Single engine:     bash trigger-scan.sh --engine <name> <scan-run-id>
#   Watch progress:    bash trigger-scan.sh --watch <workflow-name>
#   List recent:       bash trigger-scan.sh --list
#
# Examples:
#   bash trigger-scan.sh $(uuidgen) test-tenant-002 588989875114
#   bash trigger-scan.sh --engine threat abc123-scan-id
#   bash trigger-scan.sh --watch cspm-scan-abc12

set -euo pipefail
NS="threat-engine-engines"

case "${1:-}" in
  --engine)
    ENGINE="${2:?Usage: trigger-scan.sh --engine <name> <scan-run-id>}"
    SCAN_ID="${3:?Usage: trigger-scan.sh --engine <name> <scan-run-id>}"
    echo "=== Triggering single engine: $ENGINE ==="
    argo submit -n $NS \
      --from wftmpl/cspm-single-engine \
      --generate-name "cspm-${ENGINE}-" \
      -p engine="$ENGINE" \
      -p scan-run-id="$SCAN_ID"
    ;;

  --watch)
    WF_NAME="${2:?Usage: trigger-scan.sh --watch <workflow-name>}"
    argo watch -n $NS "$WF_NAME"
    ;;

  --list)
    argo list -n $NS --status Running,Succeeded,Failed -l app=cspm-pipeline 2>/dev/null || \
    argo list -n $NS 2>/dev/null || \
    echo "Install argo CLI: brew install argo"
    ;;

  --status)
    SCAN_ID="${2:?Usage: trigger-scan.sh --status <scan-run-id>}"
    # Find workflow by label
    argo list -n $NS -l "scan-run-id=$SCAN_ID" 2>/dev/null || \
    echo "No workflow found for scan-run-id=$SCAN_ID"
    ;;

  ""|--help)
    echo "Usage:"
    echo "  Full pipeline:  $0 <scan-run-id> <tenant-id> <account-id> [provider]"
    echo "  Single engine:  $0 --engine <name> <scan-run-id>"
    echo "  Watch:          $0 --watch <workflow-name>"
    echo "  List recent:    $0 --list"
    echo ""
    echo "Engines: discovery, check, inventory, threat, compliance, iam, datasec"
    ;;

  *)
    SCAN_ID="${1}"
    TENANT_ID="${2:?Usage: trigger-scan.sh <scan-run-id> <tenant-id> <account-id> [provider]}"
    ACCOUNT_ID="${3:?Usage: trigger-scan.sh <scan-run-id> <tenant-id> <account-id> [provider]}"
    PROVIDER="${4:-aws}"

    echo "=== Triggering full CSPM pipeline ==="
    echo "  scan-run-id: $SCAN_ID"
    echo "  tenant:      $TENANT_ID"
    echo "  account:     $ACCOUNT_ID"
    echo "  provider:    $PROVIDER"
    echo ""

    argo submit -n $NS \
      --from wftmpl/cspm-scan-pipeline \
      --generate-name "cspm-scan-" \
      -p scan-run-id="$SCAN_ID" \
      -p tenant-id="$TENANT_ID" \
      -p account-id="$ACCOUNT_ID" \
      -p provider="$PROVIDER" \
      --labels "scan-run-id=$SCAN_ID"

    echo ""
    echo "Watch: $0 --watch cspm-scan-<suffix>"
    ;;
esac
