# File Cleanup Analysis

## Files to UPDATE (Outdated References)

### 1. `build-and-push-engines.sh` ❌ OUTDATED
- **Issue**: Uses old folder names (`aws_compliance_python_engine`, `yaml-rule-builder`)
- **Action**: Update to use `configScan_engines/` and `rule_engine/`
- **Status**: Needs update

### 2. `cleanup.sh` ❌ OUTDATED  
- **Issue**: References old folder names
- **Action**: Update or remove (we have `cleanup-workspace.sh` which is better)
- **Status**: Can be removed (replaced by `cleanup-workspace.sh`)

### 3. `test-engines-local.sh` ❌ OUTDATED
- **Issue**: References old `engines/` folder (should be `configScan_engines/`)
- **Action**: Update paths
- **Status**: Needs update

### 4. `deploy-all-engines.sh` ⚠️ CHECK
- **Issue**: May reference old paths
- **Action**: Verify and update if needed
- **Status**: Needs review

### 5. `rebuild-and-redeploy.sh` ⚠️ CHECK
- **Issue**: May reference old deployment names
- **Action**: Verify and update if needed
- **Status**: Needs review

## Files to KEEP (Essential)

### Configuration Files ✅
- `.dockerignore` - Essential for Docker builds
- `.gitignore` - Essential for Git
- `aws-auth-configmap.yaml` - Needed for EKS cluster access

### Active Scripts ✅
- `setup-local-databases.sh` - Active database setup
- `setup-s3-folders.sh` - Active S3 setup
- `setup-s3-iam-permissions.sh` - Active IAM setup
- `run-full-aws-scan.sh` - Active scan script
- `monitor-scan.sh` - Active monitoring script
- `start-postgres-and-setup.sh` - Active PostgreSQL setup
- `eks-cost-reduction.sh` - Active cost optimization
- `make-s3-public.sh` - Active S3 configuration

### Active Directories ✅
- `unified-engine/` - Still in use (dev environment)
- `scripts/` - Contains active scripts (`init-rds-schema.sh`, etc.)
- `deployment/` - Active deployment configs

## Documentation Files (Can Consolidate)

### Historical/Summary Docs (Can Archive)
- `CLEANUP_SUMMARY.md` - Historical record (completed)
- `FOLDER_RENAME_SUMMARY.md` - Historical record (completed)
- `WORKSPACE_REORGANIZATION.md` - Historical record (completed)
- `THREAT_ENGINE_IMPLEMENTATION.md` - Recent, but can be moved to `threat-engine/README.md`

### Active Documentation ✅
- `CURRENT_DEPLOYMENT_STATUS.md` - Active status doc
- `DATABASE_SETUP.md` - Active reference
- `DEPLOYMENT_GUIDE.md` - Active reference
- `ENGINE_DEPLOYMENT_GUIDE.md` - Active reference
- `EKS_CLUSTER_HANDOVER.md` - Active reference
- `EKS_CLUSTER_SIZE_RECOMMENDATIONS.md` - Active reference
- `EKS_COST_OPTIMIZATION.md` - Active reference
- `EKS_SERVICE_INVENTORY_ap-south-1.md` - Active reference

## Tools Folder

### Status: ⚠️ DEVELOPMENT TOOLS
- Contains scripts for rule generation, validation, analysis
- **Recommendation**: 
  - Keep if still actively used for development
  - Archive to `tools-archive/` if not actively used
  - Or move to separate repo for development tools

## Recommended Actions

1. **Update outdated scripts** (5 files)
2. **Remove redundant cleanup script** (`cleanup.sh` - replaced by `cleanup-workspace.sh`)
3. **Consolidate documentation** (move historical docs to `docs/archive/`)
4. **Archive tools folder** (if not actively used)

