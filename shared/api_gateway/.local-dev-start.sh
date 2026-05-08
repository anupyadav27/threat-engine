#!/bin/bash
# Local-dev launcher for the API gateway.
# Starts uvicorn with engine URLs pointing at the cluster ingress NLB,
# auth bypass enabled, and synthesized X-Auth-Context for every request.

set -euo pipefail

cd "$(dirname "$0")"

NLB="${NLB_HOST:-http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com}"

# Engine URLs via cluster ingress (rewrite-target /$2 strips the prefix)
export DISCOVERIES_ENGINE_URL="$NLB/discoveries"
export INVENTORY_ENGINE_URL="$NLB/inventory"
export THREAT_ENGINE_URL="$NLB/threat"
export CHECK_ENGINE_URL="$NLB/check"
export COMPLIANCE_ENGINE_URL="$NLB/compliance"
export IAM_ENGINE_URL="$NLB/iam"
export DATASEC_ENGINE_URL="$NLB/datasec"
export ENCRYPTION_ENGINE_URL="$NLB/encryption"
export SECOPS_ENGINE_URL="$NLB/secops"
export RISK_ENGINE_URL="$NLB/risk"
export ONBOARDING_ENGINE_URL="$NLB/onboarding"
export RULE_ENGINE_URL="$NLB/rule"
export NETWORK_ENGINE_URL="$NLB/network"
export CIEM_ENGINE_URL="$NLB/ciem"
export AI_SECURITY_ENGINE_URL="$NLB/ai-security"
export CONTAINER_SEC_ENGINE_URL="$NLB/container-security"
export CNAPP_ENGINE_URL="$NLB/cnapp"
export CWPP_ENGINE_URL="$NLB/cwpp"
export VULNERABILITY_ENGINE_URL="$NLB/vulnerability"
export DBSEC_ENGINE_URL="$NLB/dbsec"
export BILLING_ENGINE_URL="$NLB/billing"
export PLATFORM_ADMIN_ENGINE_URL="$NLB/platform-admin"

# Local-dev auth bypass (synthesizes platform_admin X-Auth-Context)
export LOCAL_DEV_BYPASS_AUTH=1
export LOCAL_DEV_TENANT_ID="${LOCAL_DEV_TENANT_ID:-default-tenant}"

# Disable DB-dependent features that AuthMiddleware would otherwise touch
export AUTH_DB_HOST=disabled.local
export USERPORTAL_DB_HOST=disabled.local

source .venv/bin/activate
exec uvicorn local_runner:app --host 127.0.0.1 --port 8000 --log-level info
