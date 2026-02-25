# Docker Image Naming - Fixed Once and For All

## Problem

Previously, there was **inconsistent naming** between build script and deployment manifest:

- **Build script** pushed to: `yadavanup84/threat-engine-onboarding:latest`
- **Deployment manifest** expected: `yadavanup84/threat-engine-onboarding-api:latest`

This caused deployments to pull old images instead of newly built ones.

---

## Root Cause

The mismatch happened because:
1. Build script used `IMAGE_NAME="threat-engine-onboarding"`
2. Kubernetes manifest used `image: yadavanup84/threat-engine-onboarding-api:latest`
3. When deploying, Kubernetes kept pulling the old `-api` image from Docker Hub

---

## Solution

### Fixed build-and-deploy.sh

Changed line 7 from:
```bash
IMAGE_NAME="threat-engine-onboarding"
```

To:
```bash
IMAGE_NAME="threat-engine-onboarding-api"
```

### How It Works Now

1. **Build Script** (`build-and-deploy.sh`):
   ```bash
   IMAGE_NAME="threat-engine-onboarding-api"
   docker build -t yadavanup84/threat-engine-onboarding-api:latest ...
   docker build -t yadavanup84/threat-engine-onboarding-api:20260217-HHMMSS ...
   docker push yadavanup84/threat-engine-onboarding-api:latest
   docker push yadavanup84/threat-engine-onboarding-api:20260217-HHMMSS
   kubectl set image deployment/engine-onboarding \
     engine-onboarding=yadavanup84/threat-engine-onboarding-api:20260217-HHMMSS
   ```

2. **Deployment Manifest** (`engine-onboarding.yaml`):
   ```yaml
   spec:
     containers:
     - name: engine-onboarding
       image: yadavanup84/threat-engine-onboarding-api:latest
   ```

3. **Consistent Names**:
   - Both use: `yadavanup84/threat-engine-onboarding-api`
   - Build script pushes with timestamped tag: `20260217-131829`
   - `kubectl set image` forces Kubernetes to pull the timestamped version
   - This ensures the LATEST code is always deployed

---

## Why This Fix Works

### Problem with `:latest` Tag

Docker's `:latest` tag is **NOT automatically updated** by Kubernetes:
- If image exists locally, Kubernetes uses cached version
- Even if you push new `:latest` to Docker Hub, pods may use old cached image
- This causes "old image" problem

### Solution: Timestamped Tags

The build script now:
1. ✅ Builds and tags image with timestamp: `threat-engine-onboarding-api:20260217-131829`
2. ✅ Also tags as `:latest` for convenience
3. ✅ Pushes BOTH tags to Docker Hub
4. ✅ **Forces deployment to use timestamped tag**
   ```bash
   kubectl set image deployment/engine-onboarding \
     engine-onboarding=yadavanup84/threat-engine-onboarding-api:20260217-131829
   ```
5. ✅ Kubernetes sees new tag, pulls fresh image, no caching!

---

## Verification

After running `./build-and-deploy.sh`, verify:

```bash
# Check pod is using timestamped image
kubectl describe pod -l app=engine-onboarding -n threat-engine-engines | grep Image:

# Should show:
# Image: yadavanup84/threat-engine-onboarding-api:20260217-HHMMSS
```

---

## Future Deployments

### Always Use build-and-deploy.sh

```bash
cd /Users/apple/Desktop/threat-engine
./engine_onboarding/deployment/build-and-deploy.sh
```

This single command:
1. ✅ Builds with correct name
2. ✅ Tags with timestamp
3. ✅ Pushes to Docker Hub
4. ✅ Deploys with timestamped tag (forces fresh pull)
5. ✅ Waits for rollout
6. ✅ Shows status

### Never Manually Edit Image Names

All image naming is now centralized in `build-and-deploy.sh`:
- `DOCKER_USERNAME="yadavanup84"`
- `IMAGE_NAME="threat-engine-onboarding-api"`

If you need to change image name:
1. Edit line 7 in `build-and-deploy.sh`
2. Update line 23 in `kubernetes/engine-onboarding.yaml`
3. Keep them identical

---

## Additional Best Practices

### 1. Image Pull Policy

The deployment already uses:
```yaml
imagePullPolicy: Always
```

This tells Kubernetes to ALWAYS pull the image from Docker Hub, never use cache. Combined with timestamped tags, this guarantees fresh deployments.

### 2. Docker Hub Authentication

Your Docker credentials are stored in:
- **Docker Desktop credential store** (`credsStore: "desktop"`)
- Located at: `~/.docker/config.json`

This allows non-interactive `docker push` commands in scripts.

### 3. Memory Resource Limits

If you encounter "Insufficient memory" errors:

**Quick Fix:**
```bash
# Delete old pod manually to free memory
kubectl delete pod <old-pod-name> -n threat-engine-engines
```

**Permanent Fix:**
- Reduce memory requests in deployment manifest
- OR scale up EKS node group to larger instance types
- Current: t3.medium (4GB RAM)
- Recommended: t3.large (8GB RAM) for more headroom

---

## Summary

✅ **Fixed Once and For All:**
- Build script and deployment manifest now use identical image names
- Timestamped tags prevent Docker cache issues
- `imagePullPolicy: Always` forces fresh pulls
- Single command deployment script handles everything

✅ **No More Old Image Issues:**
- Every build creates unique timestamped tag
- Kubernetes deployment forced to use new tag
- Old images never accidentally deployed

✅ **Simple Future Deployments:**
```bash
./engine_onboarding/deployment/build-and-deploy.sh
```

That's it! No more image naming confusion! 🎉
