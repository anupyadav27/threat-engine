-- Migration: Add resource_uid column to standardize across all CSPs
-- For AWS: resource_uid = ARN
-- For Azure: resource_uid = Resource ID
-- For GCP: resource_uid = Resource Name

-- Step 1: Add resource_uid column to discoveries table
ALTER TABLE discoveries ADD COLUMN IF NOT EXISTS resource_uid TEXT;

-- Step 2: Add resource_uid column to check_results table
ALTER TABLE check_results ADD COLUMN IF NOT EXISTS resource_uid TEXT;

-- Step 3: Add resource_uid column to discovery_history table (if exists)
ALTER TABLE discovery_history ADD COLUMN IF NOT EXISTS resource_uid TEXT;

-- Step 4: Backfill resource_uid from resource_arn for AWS resources
-- For AWS: resource_uid = resource_arn (same value)
UPDATE discoveries SET resource_uid = resource_arn WHERE resource_uid IS NULL AND resource_arn IS NOT NULL;
UPDATE check_results SET resource_uid = resource_arn WHERE resource_uid IS NULL AND resource_arn IS NOT NULL;
UPDATE discovery_history SET resource_uid = resource_arn WHERE resource_uid IS NULL AND resource_arn IS NOT NULL;

-- Step 5: Create indexes on resource_uid for efficient queries
CREATE INDEX IF NOT EXISTS idx_discoveries_resource_uid ON discoveries(resource_uid);
CREATE INDEX IF NOT EXISTS idx_check_results_resource_uid ON check_results(resource_uid);
CREATE INDEX IF NOT EXISTS idx_discovery_history_resource_uid ON discovery_history(resource_uid);

-- Step 6: Create composite indexes for common queries
CREATE INDEX IF NOT EXISTS idx_discoveries_tenant_uid ON discoveries(tenant_id, resource_uid);
CREATE INDEX IF NOT EXISTS idx_check_results_tenant_uid ON check_results(tenant_id, resource_uid);

-- Step 7: Add comments for documentation
COMMENT ON COLUMN discoveries.resource_uid IS 'Stable unique identifier (ARN for AWS, Resource ID for Azure, Resource Name for GCP)';
COMMENT ON COLUMN check_results.resource_uid IS 'Stable unique identifier (ARN for AWS, Resource ID for Azure, Resource Name for GCP)';
COMMENT ON COLUMN discoveries.resource_arn IS 'AWS-specific ARN (deprecated - use resource_uid)';
COMMENT ON COLUMN check_results.resource_arn IS 'AWS-specific ARN (deprecated - use resource_uid)';
