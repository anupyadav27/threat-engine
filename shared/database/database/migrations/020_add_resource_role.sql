-- Migration 020: Add resource_role column to service_classification
-- Classifies resources as 'primary' (shown in diagram boxes) or 'supporting' (shown in reference table)
--
-- Primary: workload resources that users deploy (EC2, RDS, Lambda, S3, ALB, EKS, etc.)
-- Supporting: infrastructure/service resources that attach to primaries (IAM, SG, KMS, ENI, etc.)

ALTER TABLE service_classification
  ADD COLUMN IF NOT EXISTS resource_role VARCHAR(20) DEFAULT 'primary';

-- Set supporting resources based on category
UPDATE service_classification SET resource_role = 'supporting' WHERE category IN (
  'identity', 'security', 'encryption', 'monitoring', 'management'
);

-- Network category: mostly supporting (VPC infra), except edge resources which are primary
UPDATE service_classification SET resource_role = 'supporting' WHERE category = 'network';

-- Edge category stays primary (CloudFront, ALB, API Gateway, Route53)
-- Compute, Container, Database, Storage, Messaging, Analytics, AI_ML, IoT stay primary

-- Override: EBS volumes and snapshots are supporting (attached storage)
UPDATE service_classification SET resource_role = 'supporting'
  WHERE subcategory IN ('block', 'snapshot', 'ebs');

-- Override: Some storage like EBS is supporting but S3/EFS are primary
-- (already correct since storage category defaults to primary)

-- Add index for quick filtering
CREATE INDEX IF NOT EXISTS idx_sc_resource_role ON service_classification(resource_role);

-- Verify distribution
-- SELECT resource_role, COUNT(*) FROM service_classification GROUP BY resource_role;
