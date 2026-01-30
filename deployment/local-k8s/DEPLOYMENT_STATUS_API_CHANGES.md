# API Changes Deployment Status

## Issue
Docker build is caching layers even with `--no-cache`, preventing updated code from being included in the image.

## Changes Made
1. ✅ Code updated: `/{provider}/methods` → `/{provider}/auth-methods` 
2. ✅ Code updated: `DELETE /scan/{id}` now mutes instead of deletes
3. ✅ Test script created: `scripts/test_complete_user_flow.sh`

## Problem
- Local file verified: `/Users/apple/Desktop/threat-engine/engine_onboarding/api/onboarding.py` has `auth-methods`
- Docker image: Still contains old `/methods` route
- Cause: Docker layer caching or build context issue

## Solution Options

### Option 1: Simple kubectl exec to verify (CURRENT)
Since the changes are API-only (no new dependencies), we can verify deployment works and update docs:

```bash
# Current deployed endpoints:
curl http://localhost:30010/api/v1/onboarding/aws/methods  # OLD - still works
curl -X DELETE http://localhost:30002/api/v1/scan/{id}    # NEW - mutes scan

# Document both endpoints during transition period
```

### Option 2: Force fresh Docker build
```bash
cd /Users/apple/Desktop/threat-engine

# Remove all cache
docker system prune -a --volumes -f

# Build with explicit context
docker build \
  --pull \
  --no-cache \
  --platform linux/amd64 \
  -t yadavanup84/onboarding-service:$(date +%Y%m%d-%H%M%S) \
  -f engine_onboarding/Dockerfile \
  .

# Push and update deployment
docker push yadavanup84/onboarding-service:20260125-HHMMSS
kubectl set image deployment/onboarding-service \
  -n threat-engine-local \
  onboarding-service=yadavanup84/onboarding-service:20260125-HHMMSS
```

### Option 3: Update deployment YAML directly
Edit `deployment/local-k8s/onboarding-deployment.yaml`:

```yaml
spec:
  containers:
  - name: onboarding-service
    image: yadavanup84/onboarding-service:NEW_TAG_HERE
    imagePullPolicy: Always
```

## Status
- ConfigScan changes: ✅ Deployed (mute functionality working)
- Onboarding changes: ⏸️  Code ready, image build pending
- Test script: ✅ Created and ready to use

## Next Steps
1. Clear Docker cache completely
2. Rebuild onboarding image with timestamp tag
3. Update deployment to use new tag
4. Test both endpoints
