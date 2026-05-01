#!/usr/bin/env bash
# scan-status.sh — Show pipeline scan status at a glance
# Usage: ./scan-status.sh [scan_run_id]
# If no scan_run_id given, shows the latest scan.

set -euo pipefail

DB_HOST="postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com"
DB_USER="postgres"
DB_PORT="5432"
PSQL_POD="psql-meta-az2"
NS="threat-engine-engines"

run_sql() {
    kubectl exec -n "$NS" "$PSQL_POD" -- \
        psql -h "$DB_HOST" -U "$DB_USER" -d "threat_engine_onboarding" \
        -t -A -F'|' -c "$1" 2>/dev/null
}

# Resolve scan_run_id
if [[ $# -ge 1 ]]; then
    SCAN_ID="$1"
else
    SCAN_ID=$(run_sql "SELECT scan_run_id FROM scan_runs ORDER BY created_at DESC LIMIT 1" | head -1)
fi

if [[ -z "$SCAN_ID" ]]; then
    echo "No scans found."
    exit 1
fi

# Fetch scan metadata
ROW=$(run_sql "SELECT scan_run_id, overall_status, tenant_id, account_id, provider, created_at FROM scan_runs WHERE scan_run_id = '$SCAN_ID'")
if [[ -z "$ROW" ]]; then
    echo "Scan $SCAN_ID not found."
    exit 1
fi

IFS='|' read -r SID STATUS TENANT ACCOUNT PROVIDER STARTED <<< "$ROW"

COMPLETED=$(run_sql "SELECT engines_completed FROM scan_runs WHERE scan_run_id = '$SCAN_ID'" | head -1)

# Argo workflow status
ARGO_STATUS=$(kubectl get pods -n "$NS" 2>/dev/null | grep "${SID:0:12}" | awk '{print $1, $3}' | head -10 || true)

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  CSPM SCAN STATUS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Scan ID  : $SID"
echo "  Status   : $STATUS"
echo "  Tenant   : $TENANT  |  Account: $ACCOUNT  |  CSP: $PROVIDER"
echo "  Started  : $STARTED"
echo ""
echo "  Engines Completed:"
echo "$COMPLETED" | tr '[]"' ' ' | tr ',' '\n' | grep -v '^[[:space:]]*$' | awk '{print "    \xe2\x9c\x93 " $1}' || echo "    (none yet)"
echo ""

if [[ -n "$ARGO_STATUS" ]]; then
    echo "  Argo Pods (active steps):"
    echo "$ARGO_STATUS" | awk '{print "    " $0}'
    echo ""
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
exit 0
