#!/bin/bash
# Trigger a CSPM scan via Argo Workflows
#
# Usage:
#   Full pipeline:     bash trigger-scan.sh <scan-run-id> <tenant-id> <account-id> [provider] [credential-ref]
#   Single engine:     bash trigger-scan.sh --engine <name> <scan-run-id>
#   Watch progress:    bash trigger-scan.sh --watch <workflow-name>
#   List recent:       bash trigger-scan.sh --list
#
# Examples (AWS):
#   bash trigger-scan.sh $(uuidgen) test-tenant-002 588989875114
#   bash trigger-scan.sh $(uuidgen) test-tenant-002 588989875114 aws threat-engine/account/588989875114
#
# Examples (Azure):
#   AZURE_SUB=f6d24b5d-51ed-47b7-9f6a-0ad194156b5e
#   bash trigger-scan.sh $(uuidgen) my-tenant $AZURE_SUB azure threat-engine/azure/$AZURE_SUB
#
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
    echo "  Full pipeline:  $0 <scan-run-id> <tenant-id> <account-id> [provider] [credential-ref]"
    echo "  Single engine:  $0 --engine <name> <scan-run-id>"
    echo "  Watch:          $0 --watch <workflow-name>"
    echo "  List recent:    $0 --list"
    echo ""
    echo "  provider defaults to 'aws'"
    echo "  credential-ref defaults to 'threat-engine/account/<account-id>'"
    echo "  For Azure: pass provider=azure credential-ref=threat-engine/azure/<subscription-id>"
    echo ""
    echo "Engines: discovery, check, inventory, threat, compliance, iam, datasec"
    ;;

  *)
    SCAN_ID="${1}"
    TENANT_ID="${2:?Usage: trigger-scan.sh <scan-run-id> <tenant-id> <account-id> [provider] [credential-ref]}"
    ACCOUNT_ID="${3:?Usage: trigger-scan.sh <scan-run-id> <tenant-id> <account-id> [provider] [credential-ref]}"
    PROVIDER="${4:-aws}"
    CREDENTIAL_REF="${5:-threat-engine/account/${ACCOUNT_ID}}"
    INCLUDE_SERVICES="${6:-}"

    # Derive credential-type from provider
    if [ "$PROVIDER" = "azure" ]; then
      CREDENTIAL_TYPE="service_principal"
    elif [ "$PROVIDER" = "gcp" ]; then
      CREDENTIAL_TYPE="service_account"
    else
      CREDENTIAL_TYPE="access_key"
    fi

    echo "=== Triggering full CSPM pipeline ==="
    echo "  scan-run-id:     $SCAN_ID"
    echo "  tenant:          $TENANT_ID"
    echo "  account:         $ACCOUNT_ID"
    echo "  provider:        $PROVIDER"
    echo "  credential-ref:  $CREDENTIAL_REF"
    echo "  credential-type: $CREDENTIAL_TYPE"
    [ -n "$INCLUDE_SERVICES" ] && echo "  services:        $INCLUDE_SERVICES"
    echo ""

    argo submit -n $NS \
      --from wftmpl/cspm-scan-pipeline \
      --generate-name "cspm-scan-" \
      -p scan-run-id="$SCAN_ID" \
      -p tenant-id="$TENANT_ID" \
      -p account-id="$ACCOUNT_ID" \
      -p provider="$PROVIDER" \
      -p credential-ref="$CREDENTIAL_REF" \
      -p credential-type="$CREDENTIAL_TYPE" \
      -p include-services="$INCLUDE_SERVICES" \
      --labels "scan-run-id=$SCAN_ID"

    echo ""
    echo "Watch: $0 --watch cspm-scan-<suffix>"
    ;;
esac
