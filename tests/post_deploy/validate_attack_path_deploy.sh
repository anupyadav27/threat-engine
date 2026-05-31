#!/usr/bin/env bash
# ==============================================================================
# Post-Deploy Validation: engine-attack-path (AP-P2-07)
#
# Architecture reference: Section 10 — Deployment.
# Follows TESTING_QUALITY.md Level 10 — Post-Deploy Validation.
#
# Run immediately after:
#   kubectl rollout status deployment/engine-attack-path -n threat-engine-engines
#
# Usage:
#   INTENDED_TAG=v-attack-path1 bash tests/post_deploy/validate_attack_path_deploy.sh
#
# Required env vars (defaults to cluster-internal):
#   INTENDED_TAG         — image tag that was just deployed (required)
#   GATEWAY_URL          — API gateway URL (default: cluster NLB)
#   TENANT_ID            — tenant to use for BFF smoke test
#   NAMESPACE            — K8s namespace (default: threat-engine-engines)
#   ENGINE_NAME          — deployment name (default: engine-attack-path)
#   CONTAINER_NAME       — container name (default: engine-attack-path)
#   ENGINE_PORT          — container port (default: 8025)
#   ENGINE_POD_PREFIX    — pod label selector (default: app=engine-attack-path)
# ==============================================================================

set -euo pipefail

NAMESPACE="${NAMESPACE:-threat-engine-engines}"
ENGINE_NAME="${ENGINE_NAME:-engine-attack-path}"
CONTAINER_NAME="${CONTAINER_NAME:-engine-attack-path}"
ENGINE_PORT="${ENGINE_PORT:-8025}"
ENGINE_POD_LABEL="${ENGINE_POD_LABEL:-app=engine-attack-path}"
GATEWAY_URL="${GATEWAY_URL:-http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com}"
TENANT_ID="${TENANT_ID:-my-tenant}"
INTENDED_TAG="${INTENDED_TAG:-}"

PASS=0
FAIL=0

# ── Colour output ──────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}  [PASS]${NC} $1"; ((PASS++)); }
fail() { echo -e "${RED}  [FAIL]${NC} $1"; ((FAIL++)); }
warn() { echo -e "${YELLOW}  [WARN]${NC} $1"; }
info() { echo -e "  [INFO] $1"; }

echo ""
echo "============================================================"
echo " Post-Deploy Validation: ${ENGINE_NAME}"
echo " Namespace  : ${NAMESPACE}"
echo " Gateway    : ${GATEWAY_URL}"
echo " Intended   : ${INTENDED_TAG:-'(not set)'}"
echo "============================================================"
echo ""

# ==============================================================================
# CHECK 0: Image tag verification (MANDATORY — VSCode YAML linter can revert tags)
# ==============================================================================
echo "--- CHECK 0: Image tag verification ---"

if [ -z "${INTENDED_TAG}" ]; then
  warn "INTENDED_TAG not set — skipping image tag check. Set it to enforce tag verification."
else
  RUNNING_IMAGE=$(kubectl get pods -n "${NAMESPACE}" \
    -l "${ENGINE_POD_LABEL}" \
    -o jsonpath='{.items[0].spec.containers[0].image}' 2>/dev/null || echo "")

  if [ -z "${RUNNING_IMAGE}" ]; then
    fail "Could not find running pod with label ${ENGINE_POD_LABEL}"
  else
    info "Running image: ${RUNNING_IMAGE}"
    if echo "${RUNNING_IMAGE}" | grep -q "${INTENDED_TAG}"; then
      ok "Pod image contains intended tag '${INTENDED_TAG}'"
    else
      fail "Pod image '${RUNNING_IMAGE}' does NOT match intended tag '${INTENDED_TAG}'"
      warn "The VSCode YAML linter may have silently reverted the image tag in the manifest."
      warn "Fix: kubectl set image deployment/${ENGINE_NAME} ${CONTAINER_NAME}=yadavanup84/${ENGINE_NAME}:${INTENDED_TAG} -n ${NAMESPACE}"
    fi
  fi
fi

# ==============================================================================
# CHECK 1: Health check — liveness (GET /api/v1/health/live)
# ==============================================================================
echo ""
echo "--- CHECK 1: Health check — liveness ---"

# Port-forward to the service for health checks
PF_PORT=$((RANDOM + 10000))
kubectl port-forward "svc/${ENGINE_NAME}" "${PF_PORT}:80" -n "${NAMESPACE}" &>/dev/null &
PF_PID=$!
sleep 2  # Wait for port-forward to establish

LIVE_STATUS=$(python3 -c "
import urllib.request, sys
try:
    req = urllib.request.Request('http://127.0.0.1:${PF_PORT}/api/v1/health/live')
    with urllib.request.urlopen(req, timeout=10) as r:
        import json; d=json.loads(r.read())
        print(str(r.status) + '|' + d.get('status','unknown'))
except Exception as e:
    print('0|error:' + str(e))
" 2>/dev/null || echo "0|error:python failed")

HTTP_CODE=$(echo "${LIVE_STATUS}" | cut -d'|' -f1)
BODY_STATUS=$(echo "${LIVE_STATUS}" | cut -d'|' -f2)

if [ "${HTTP_CODE}" = "200" ] && [ "${BODY_STATUS}" = "ok" ]; then
  ok "/api/v1/health/live → 200 {\"status\": \"ok\"}"
else
  fail "/api/v1/health/live → HTTP ${HTTP_CODE}, status=${BODY_STATUS}"
fi

# ==============================================================================
# CHECK 2: Health check — readiness (GET /api/v1/health/ready)
# ==============================================================================
echo ""
echo "--- CHECK 2: Health check — readiness (DB connection) ---"

READY_STATUS=$(python3 -c "
import urllib.request, sys
try:
    req = urllib.request.Request('http://127.0.0.1:${PF_PORT}/api/v1/health/ready')
    with urllib.request.urlopen(req, timeout=10) as r:
        import json; d=json.loads(r.read())
        print(str(r.status) + '|' + d.get('status','unknown'))
except Exception as e:
    print('0|error:' + str(e))
" 2>/dev/null || echo "0|error:python failed")

READY_HTTP=$(echo "${READY_STATUS}" | cut -d'|' -f1)
READY_BODY=$(echo "${READY_STATUS}" | cut -d'|' -f2)

if [ "${READY_HTTP}" = "200" ] && [ "${READY_BODY}" = "ready" ]; then
  ok "/api/v1/health/ready → 200 {\"status\": \"ready\"}"
else
  fail "/api/v1/health/ready → HTTP ${READY_HTTP}, status=${READY_BODY} (DB connection issue?)"
fi

# Clean up port-forward
kill "${PF_PID}" 2>/dev/null || true

# ==============================================================================
# CHECK 3: Log check — no ERROR lines in first 60 seconds
# ==============================================================================
echo ""
echo "--- CHECK 3: Log check — no ERROR lines in first 60s ---"

ERROR_COUNT=$(kubectl logs -l "${ENGINE_POD_LABEL}" -n "${NAMESPACE}" \
  --since=60s 2>/dev/null | grep -c "ERROR" || echo "0")

if [ "${ERROR_COUNT}" -eq "0" ]; then
  ok "0 ERROR lines in logs (last 60s)"
else
  fail "${ERROR_COUNT} ERROR line(s) found in logs (last 60s)"
  info "View errors: kubectl logs -l ${ENGINE_POD_LABEL} -n ${NAMESPACE} --since=60s | grep ERROR"
fi

# ==============================================================================
# CHECK 4: BFF smoke — GET /views/attack-paths returns 200
# ==============================================================================
echo ""
echo "--- CHECK 4: BFF smoke — /api/v1/views/attack-paths ---"

BFF_STATUS=$(python3 -c "
import urllib.request, urllib.error, json, sys
url = '${GATEWAY_URL}/api/v1/views/attack-paths?tenant_id=${TENANT_ID}'
try:
    req = urllib.request.Request(url, headers={'Accept': 'application/json'})
    with urllib.request.urlopen(req, timeout=15) as r:
        d = json.loads(r.read())
        has_kpis = isinstance(d.get('kpis'), dict)
        print(str(r.status) + '|' + str(has_kpis))
except urllib.error.HTTPError as e:
    print(str(e.code) + '|False')
except Exception as e:
    print('0|error:' + str(e))
" 2>/dev/null || echo "0|error:python failed")

BFF_HTTP=$(echo "${BFF_STATUS}" | cut -d'|' -f1)
BFF_HAS_KPIS=$(echo "${BFF_STATUS}" | cut -d'|' -f2)

if [ "${BFF_HTTP}" = "200" ] && [ "${BFF_HAS_KPIS}" = "True" ]; then
  ok "BFF /views/attack-paths → 200 with non-null kpis"
elif [ "${BFF_HTTP}" = "401" ] || [ "${BFF_HTTP}" = "403" ]; then
  warn "BFF /views/attack-paths → ${BFF_HTTP} (auth required — set valid GATEWAY_TOKEN for full smoke test)"
elif [ "${BFF_HTTP}" = "503" ]; then
  fail "BFF /views/attack-paths → 503 (engine unreachable — engine may be down or route not registered)"
else
  fail "BFF /views/attack-paths → HTTP ${BFF_HTTP}, kpis=${BFF_HAS_KPIS}"
fi

# ==============================================================================
# CHECK 5: DB connectivity — engine can query attack_paths table
# ==============================================================================
echo ""
echo "--- CHECK 5: DB connectivity --- "

DB_CHECK=$(kubectl exec "deployment/${ENGINE_NAME}" -n "${NAMESPACE}" -- \
  python3 -c "
import os, sys
try:
    import psycopg2
    conn = psycopg2.connect(
        host=os.environ.get('ATTACK_PATH_DB_HOST',''),
        dbname=os.environ.get('ATTACK_PATH_DB_NAME','threat_engine_attack_path'),
        user=os.environ.get('ATTACK_PATH_DB_USER',''),
        password=os.environ.get('ATTACK_PATH_DB_PASSWORD',''),
        connect_timeout=5,
    )
    cur = conn.cursor()
    cur.execute('SELECT COUNT(*) FROM attack_paths LIMIT 1')
    count = cur.fetchone()[0]
    conn.close()
    print('ok|' + str(count))
except Exception as e:
    print('error|' + str(e))
" 2>/dev/null || echo "error|exec failed")

DB_RESULT=$(echo "${DB_CHECK}" | cut -d'|' -f1)

if [ "${DB_RESULT}" = "ok" ]; then
  ROW_COUNT=$(echo "${DB_CHECK}" | cut -d'|' -f2)
  ok "attack_paths table accessible — ${ROW_COUNT} total rows"
else
  fail "DB connection failed: $(echo "${DB_CHECK}" | cut -d'|' -f2)"
fi

# ==============================================================================
# CHECK 6: Neo4j connectivity
# ==============================================================================
echo ""
echo "--- CHECK 6: Neo4j connectivity ---"

NEO4J_CHECK=$(kubectl exec "deployment/${ENGINE_NAME}" -n "${NAMESPACE}" -- \
  python3 -c "
import os
try:
    from neo4j import GraphDatabase
    uri = os.environ.get('NEO4J_URI','')
    user = os.environ.get('NEO4J_USER','neo4j')
    pw = os.environ.get('NEO4J_PASSWORD','')
    if not uri:
        print('skip|NEO4J_URI not set')
    else:
        driver = GraphDatabase.driver(uri, auth=(user, pw))
        with driver.session() as s:
            s.run('RETURN 1')
        driver.close()
        print('ok|connected')
except Exception as e:
    print('error|' + str(e)[:100])
" 2>/dev/null || echo "skip|exec failed")

NEO4J_RESULT=$(echo "${NEO4J_CHECK}" | cut -d'|' -f1)

case "${NEO4J_RESULT}" in
  ok)    ok "Neo4j connectivity verified" ;;
  skip)  warn "Neo4j check skipped: $(echo "${NEO4J_CHECK}" | cut -d'|' -f2)" ;;
  error) fail "Neo4j connection failed: $(echo "${NEO4J_CHECK}" | cut -d'|' -f2)" ;;
  *)     warn "Neo4j check returned unexpected result: ${NEO4J_CHECK}" ;;
esac

# ==============================================================================
# SUMMARY
# ==============================================================================
echo ""
echo "============================================================"
echo " Post-Deploy Summary"
echo "   PASS: ${PASS}"
echo "   FAIL: ${FAIL}"
echo "============================================================"

if [ "${FAIL}" -gt 0 ]; then
  echo ""
  echo -e "${RED}POST-DEPLOY VALIDATION FAILED — IMMEDIATE ROLLBACK REQUIRED${NC}"
  echo ""
  echo "Rollback command:"
  echo "  kubectl rollout undo deployment/${ENGINE_NAME} -n ${NAMESPACE}"
  echo ""
  echo "Or force a specific tag:"
  echo "  kubectl set image deployment/${ENGINE_NAME} ${CONTAINER_NAME}=yadavanup84/${ENGINE_NAME}:<previous-tag> -n ${NAMESPACE}"
  exit 1
else
  echo ""
  echo -e "${GREEN}ALL CHECKS PASSED — deploy is healthy${NC}"
  echo ""
  exit 0
fi
