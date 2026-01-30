#!/bin/bash
# Build and push images from threat-engine repo. Optionally skip if already on Docker Hub.
# Usage: ./build-and-push-from-repo.sh [DOCKERHUB_USER]   e.g. ./build-and-push-from-repo.sh yadavanup84
# Env: FORCE_BUILD=1 to build even if image exists on Hub. SKIP_PUSH=1 to only build.

set -e

DOCKERHUB_USER="${1:-yadavanup84}"
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

image_exists() {
  docker manifest inspect "$1" >/dev/null 2>&1
}

build_push() {
  local img="$1"
  local dockerfile="$2"
  local ctx="$3"
  if [ -z "$ctx" ]; then ctx="$REPO_ROOT"; fi
  if [ -n "$FORCE_BUILD" ] || ! image_exists "$img"; then
    echo "Building $img ..."
    docker build -t "$img" -f "$dockerfile" "$ctx" || { echo "Build failed: $img"; return 1; }
    if [ -z "$SKIP_PUSH" ]; then docker push "$img" && echo "Pushed $img"; else echo "Built (skip push): $img"; fi
  else
    echo "Skip (exists): $img"
  fi
}

echo "Using Docker Hub user: $DOCKERHUB_USER"
echo "Repo root: $REPO_ROOT"

# CSP compliance engines (build context = repo root)
build_push "$DOCKERHUB_USER/threat-engine-aws-compliance-engine:latest" \
  engine_configscan/engine_configscan_aws/Dockerfile .
build_push "$DOCKERHUB_USER/threat-engine-azure-compliance:latest" \
  engine_configscan/engine_configscan_azure/Dockerfile .
build_push "$DOCKERHUB_USER/threat-engine-gcp-compliance:latest" \
  engine_configscan/engine_configscan_gcp/Dockerfile .
build_push "$DOCKERHUB_USER/threat-engine-alicloud-compliance:latest" \
  engine_configscan/engine_configscan_alicloud/Dockerfile .
build_push "$DOCKERHUB_USER/threat-engine-oci-compliance:latest" \
  engine_configscan/engine_configscan_oci/Dockerfile .
build_push "$DOCKERHUB_USER/threat-engine-ibm-compliance:latest" \
  engine_configscan/engine_configscan_ibm/Dockerfile .

# YAML rule builder = engine_rule
build_push "$DOCKERHUB_USER/threat-engine-yaml-rule-builder:latest" \
  engine_rule/Dockerfile .

# Compliance aggregator API
build_push "$DOCKERHUB_USER/threat-engine-compliance-engine:latest" \
  engine_compliance/Dockerfile .

# Onboarding API (context = repo root)
build_push "$DOCKERHUB_USER/threat-engine-onboarding-api:latest" \
  engine_onboarding/Dockerfile .

# Scheduler (context = engine_onboarding so COPY . ./onboarding/ works)
build_push "$DOCKERHUB_USER/threat-engine-scheduler:latest" \
  engine_onboarding/scheduler/Dockerfile "$REPO_ROOT/engine_onboarding"

# Inventory & Threat
build_push "$DOCKERHUB_USER/inventory-engine:latest" \
  engine_inventory/Dockerfile .
build_push "$DOCKERHUB_USER/threat-engine:latest" \
  engine_threat/Dockerfile .

echo "Done. Deploy with: kubectl apply -f deployment/aws/eks/ -n threat-engine-engines"
