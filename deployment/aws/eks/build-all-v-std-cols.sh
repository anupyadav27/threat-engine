#!/bin/bash
# Build all engine Docker images with v-std-cols tag
# Run from repo root: bash deployment/aws/eks/build-all-v-std-cols.sh
#
# Builds in batches of 3 to avoid Docker Desktop blob corruption

set -euo pipefail
cd /Users/apple/Desktop/threat-engine

TAG="v-std-cols"
FAILED=()

build() {
  local name="$1" dockerfile="$2"
  echo "=== Building $name ==="
  if docker build -t "$name:$TAG" -f "$dockerfile" . ; then
    echo "=== $name OK ==="
  else
    echo "=== $name FAILED ==="
    FAILED+=("$name")
  fi
}

echo "=========================================="
echo " Building all engines with tag: $TAG"
echo "=========================================="

# Batch 1: Core engines
build "yadavanup84/engine-discoveries"              "engines/discoveries/Dockerfile"
build "yadavanup84/engine-check"                    "engines/check/Dockerfile"
build "yadavanup84/engine-threat"                   "engines/threat/Dockerfile"

# Batch 2: Supporting engines
build "yadavanup84/inventory-engine"                "engines/inventory/Dockerfile"
build "yadavanup84/threat-engine-compliance-engine"  "engines/compliance/Dockerfile"
build "yadavanup84/engine-iam"                      "engines/iam/Dockerfile"

# Batch 3: Analysis engines + onboarding
build "yadavanup84/engine-datasec"                  "engines/datasec/Dockerfile"
build "yadavanup84/threat-engine-onboarding-api"    "engines/onboarding/Dockerfile"
build "yadavanup84/engine-risk"                     "engines/risk/Dockerfile"

# Batch 4: Infrastructure
build "yadavanup84/secops-scanner"                  "engines/secops/scanner_engine/Dockerfile"
build "yadavanup84/threat-engine-api-gateway"       "shared/api_gateway/Dockerfile"
build "yadavanup84/threat-engine-pipeline-worker"   "shared/pipeline_worker/Dockerfile"

# Batch 5: Frontend + check-aws
build "yadavanup84/engine-check"                    "engines/check/engine_check_aws/Dockerfile"  # v-std-cols-aws variant
build "yadavanup84/cspm-frontend"                   "ui_samples/Dockerfile"

echo ""
echo "=========================================="
echo " Build complete"
echo "=========================================="
docker images | grep "$TAG" | awk '{printf "  %-55s %s\n", $1":"$2, $7}'

if [ ${#FAILED[@]} -gt 0 ]; then
  echo ""
  echo "FAILED builds:"
  for f in "${FAILED[@]}"; do echo "  - $f"; done
  exit 1
fi

echo ""
echo "Next: Push all images"
echo "  docker images | grep $TAG | awk '{print \$1\":\"\$2}' | xargs -I{} docker push {}"
