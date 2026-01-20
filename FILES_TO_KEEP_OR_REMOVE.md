# Files to Keep or Remove - Summary

## ✅ KEEP (Essential Files)

### Configuration
- `.dockerignore` - Docker build optimization
- `.gitignore` - Git ignore rules
- `aws-auth-configmap.yaml` - EKS cluster access

### Active Scripts
- `setup-local-databases.sh` - Database setup
- `setup-s3-folders.sh` - S3 structure setup
- `setup-s3-iam-permissions.sh` - IAM permissions
- `run-full-aws-scan.sh` - Full scan execution
- `monitor-scan.sh` - Scan monitoring
- `start-postgres-and-setup.sh` - PostgreSQL quick start
- `eks-cost-reduction.sh` - Cost optimization
- `make-s3-public.sh` - S3 public access (if needed)
- `cleanup-workspace.sh` - Workspace cleanup

### Active Directories
- `unified-engine/` - Unified container (dev)
- `scripts/` - Active deployment scripts
- `deployment/` - Deployment configurations
- `configScan_engines/` - All CSP engines
- `compliance-engine/` - Compliance reporting
- `threat-engine/` - Threat detection
- `rule_engine/` - Rule generation
- `onboarding_engine/` - Account onboarding

### Active Documentation
- `CURRENT_DEPLOYMENT_STATUS.md` - Current status
- `DATABASE_SETUP.md` - Database reference
- `DEPLOYMENT_GUIDE.md` - Deployment guide
- `ENGINE_DEPLOYMENT_GUIDE.md` - Engine deployment
- `EKS_CLUSTER_HANDOVER.md` - EKS reference
- `EKS_CLUSTER_SIZE_RECOMMENDATIONS.md` - Sizing guide
- `EKS_COST_OPTIMIZATION.md` - Cost optimization
- `EKS_SERVICE_INVENTORY_ap-south-1.md` - Service inventory

## ❌ REMOVE (Outdated/Redundant)

### Redundant Scripts
- `cleanup.sh` - **REMOVE** (replaced by `cleanup-workspace.sh`)

### Historical Documentation (Archive)
- `CLEANUP_SUMMARY.md` - **ARCHIVE** (completed work)
- `FOLDER_RENAME_SUMMARY.md` - **ARCHIVE** (completed work)
- `WORKSPACE_REORGANIZATION.md` - **ARCHIVE** (completed work)
- `THREAT_ENGINE_IMPLEMENTATION.md` - **MOVE** to `threat-engine/IMPLEMENTATION.md`

## ⚠️ UPDATE (Outdated References - Now Fixed)

### Updated Scripts
- ✅ `build-and-push-engines.sh` - **UPDATED** (uses new folder names)
- ✅ `test-engines-local.sh` - **UPDATED** (uses `configScan_engines/`)

### Scripts to Review
- `deploy-all-engines.sh` - Review Kubernetes paths
- `rebuild-and-redeploy.sh` - Review deployment names

## 📁 Tools Folder

### Status: Development Tools
**Recommendation**: 
- **Keep** if actively used for rule generation/validation
- **Archive** to `tools-archive/` if not actively used
- Contains 30+ Python scripts for development tasks

**Decision**: Keep for now, but can be archived later if not needed.

## Quick Cleanup Commands

```bash
# Run cleanup script
./cleanup-outdated-files.sh

# Or manually:
# 1. Remove redundant cleanup.sh
rm -f cleanup.sh

# 2. Archive historical docs
mkdir -p docs/archive
mv CLEANUP_SUMMARY.md docs/archive/
mv FOLDER_RENAME_SUMMARY.md docs/archive/
mv WORKSPACE_REORGANIZATION.md docs/archive/

# 3. Move threat engine doc
mv THREAT_ENGINE_IMPLEMENTATION.md threat-engine/IMPLEMENTATION.md
```

## Summary

- **Keep**: ~15 essential scripts, ~8 active docs, all engine directories
- **Remove**: 1 redundant script (`cleanup.sh`)
- **Archive**: 3-4 historical documentation files
- **Update**: 2 scripts (✅ done), 2 scripts to review
- **Tools**: Keep for now (development tools)

**Total files to remove/archive**: ~5-6 files
**Total files to keep**: ~50+ essential files

