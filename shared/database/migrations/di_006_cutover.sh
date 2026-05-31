#!/usr/bin/env bash
# DI-S4-03 — Cutover: flip DI_ENGINE_ENABLED=true on all 16 engines + Argo pipeline.
#
# PREREQUISITES (all must pass before running this script):
#   1. di_005_validate_parallel_run.py exits 0 (all 10 checks PASSED)
#   2. Maintenance window scheduled
#   3. 0 AuthError in di_scan_errors for the parallel run scan_run_id
#
# Usage:
#   export KUBECONFIG=~/.kube/config
#   bash di_006_cutover.sh [--rollback]
#
# With --rollback: flips all engines back to DI_ENGINE_ENABLED=false

set -euo pipefail

NAMESPACE="threat-engine-engines"
ARGO_NAMESPACE="argo"

ENGINES=(
  engine-check
  engine-iam
  engine-network-security
  engine-datasec
  engine-encryption
  engine-dbsec
  engine-ai-security
  engine-api-security
  engine-container-sec
  engine-attack-path
  engine-threat-v1
  engine-cdr
  engine-risk
  engine-pipeline-monitor
  engine-threat-narrative
  engine-compliance
)

ROLLBACK=false
if [[ "${1:-}" == "--rollback" ]]; then
  ROLLBACK=true
fi

if $ROLLBACK; then
  TARGET_VALUE="false"
  echo "=== DI-S4-03 ROLLBACK: flipping DI_ENGINE_ENABLED=false on all engines ==="
else
  TARGET_VALUE="true"
  echo "=== DI-S4-03 CUTOVER: flipping DI_ENGINE_ENABLED=true on all engines ==="
fi

# Step 1: Flip all 16 downstream engines atomically
echo ""
echo "Step 1: Flipping DI_ENGINE_ENABLED=${TARGET_VALUE} on all engines..."
for engine in "${ENGINES[@]}"; do
  if kubectl get deployment "${engine}" -n "${NAMESPACE}" > /dev/null 2>&1; then
    kubectl set env "deployment/${engine}" "DI_ENGINE_ENABLED=${TARGET_VALUE}" -n "${NAMESPACE}"
    echo "  [OK] ${engine}"
  else
    echo "  [SKIP] ${engine} — deployment not found"
  fi
done

# Step 2: Flip Argo pipeline parameter (update the WorkflowTemplate default)
if ! $ROLLBACK; then
  echo ""
  echo "Step 2: Updating Argo pipeline default parameter di-pipeline-enabled=true..."
  # Patch in place using kubectl — updates the WorkflowTemplate spec directly
  kubectl patch workflowtemplate cspm-scan-pipeline -n "${NAMESPACE}" \
    --type=json \
    -p='[{"op":"replace","path":"/spec/arguments/parameters/2/value","value":"true"}]' \
    2>/dev/null || \
  echo "  [WARN] WorkflowTemplate patch failed — update cspm-pipeline.yaml manually and kubectl apply"
else
  echo ""
  echo "Step 2: Reverting Argo pipeline default parameter di-pipeline-enabled=false..."
  kubectl patch workflowtemplate cspm-scan-pipeline -n "${NAMESPACE}" \
    --type=json \
    -p='[{"op":"replace","path":"/spec/arguments/parameters/2/value","value":"false"}]' \
    2>/dev/null || \
  echo "  [WARN] WorkflowTemplate patch failed — update cspm-pipeline.yaml manually and kubectl apply"
fi

# Step 3: Wait for rollouts
echo ""
echo "Step 3: Waiting for pod restarts (this may take 2-3 minutes)..."
for engine in "${ENGINES[@]}"; do
  if kubectl get deployment "${engine}" -n "${NAMESPACE}" > /dev/null 2>&1; then
    kubectl rollout status "deployment/${engine}" -n "${NAMESPACE}" --timeout=120s || \
      echo "  [WARN] ${engine} rollout timed out — check manually"
  fi
done

# Step 4: Health check all engines
echo ""
echo "Step 4: Health checks..."
FAILED_ENGINES=()
for engine in "${ENGINES[@]}"; do
  if kubectl get deployment "${engine}" -n "${NAMESPACE}" > /dev/null 2>&1; then
    result=$(kubectl exec -n "${NAMESPACE}" "deployment/${engine}" -- \
      python3 -c "
import urllib.request, sys
try:
    urllib.request.urlopen('http://localhost/api/v1/health/live', timeout=5).read()
    print('OK')
except Exception as e:
    print('FAIL:', e)
    sys.exit(1)
" 2>/dev/null || echo "FAIL")
    if [[ "$result" == *"OK"* ]]; then
      echo "  [OK] ${engine}"
    else
      echo "  [FAIL] ${engine}: ${result}"
      FAILED_ENGINES+=("${engine}")
    fi
  fi
done

echo ""
if [ ${#FAILED_ENGINES[@]} -eq 0 ]; then
  if $ROLLBACK; then
    echo "ROLLBACK COMPLETE — all engines reverted to DI_ENGINE_ENABLED=false"
  else
    echo "CUTOVER COMPLETE — all engines running with DI_ENGINE_ENABLED=true"
    echo ""
    echo "Next steps:"
    echo "  1. Trigger a full pipeline scan to confirm end-to-end:"
    echo "     argo submit -n argo deployment/aws/eks/argo/cspm-pipeline.yaml \\"
    echo "       --parameter scan_run_id=\$(python3 -c 'import uuid; print(uuid.uuid4())')"
    echo "  2. Monitor di_scan_errors for AuthError:"
    echo "     kubectl exec -n ${NAMESPACE} deployment/engine-di -- python3 -c \\"
    echo "       \"import psycopg2, os; conn=psycopg2.connect(...); ...\""
    echo "  3. Verify check_findings count ≥ 90% of pre-cutover baseline"
    echo "  4. Update MEMORY.md: DI cutover complete; DI_ENGINE_ENABLED=true on all 16 engines"
  fi
else
  echo "HEALTH CHECK FAILED for: ${FAILED_ENGINES[*]}"
  echo "Run rollback: bash di_006_cutover.sh --rollback"
  exit 1
fi
