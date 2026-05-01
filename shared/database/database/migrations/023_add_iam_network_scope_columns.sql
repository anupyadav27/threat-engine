-- ============================================================================
-- Migration 023: Add iam_security and network_security scope columns to rule_metadata
--
-- Follows the same pattern as Migration 003 (encryption_security, container_security,
-- database_security, ai_security).
--
-- After this migration, the IAM and Network-Security engines can use
-- CategoryLoader to load their rule→module mapping from rule_metadata instead
-- of maintaining hardcoded pattern lists in Python code.
--
-- Target DB  : threat_engine_check
-- Reversible : DROP COLUMN iam_security, network_security
-- ============================================================================

BEGIN;

-- ── Schema ────────────────────────────────────────────────────────────────────
ALTER TABLE rule_metadata ADD COLUMN IF NOT EXISTS iam_security     JSONB DEFAULT '{}'::jsonb;
ALTER TABLE rule_metadata ADD COLUMN IF NOT EXISTS network_security  JSONB DEFAULT '{}'::jsonb;

-- ── IAM: identity & access management services + domain ──────────────────────
UPDATE rule_metadata
SET iam_security = '{"applicable": true}'::jsonb
WHERE (
    service IN (
        -- AWS
        'iam', 'sts', 'sso', 'identity-store', 'cognito-idp', 'cognito-identity',
        -- Azure
        'entraid', 'aad', 'managedidentity', 'serviceprincipal', 'rbac', 'pim',
        'activedirectory',
        -- GCP
        'iam', 'serviceaccount', 'workloadidentity', 'orgpolicy', 'iap',
        -- OCI
        'identity', 'identitydomains',
        -- AliCloud
        'ram'
    )
    OR domain = 'identity_and_access_management'
)
AND (iam_security IS NULL OR iam_security::text IN ('null', '{}'));

-- ── Network: networking services + domain ────────────────────────────────────
UPDATE rule_metadata
SET network_security = '{"applicable": true}'::jsonb
WHERE (
    service IN (
        -- AWS
        'ec2', 'vpc', 'elbv2', 'elb', 'wafv2', 'waf', 'shield',
        'cloudfront', 'route53', 'networkfirewall', 'directconnect',
        'apigateway', 'apigatewayv2', 'globalaccelerator',
        'vpcflowlogs', 'vpn', 'transitgateway',
        -- Azure
        'network', 'virtualnetwork', 'loadbalancer', 'applicationgateway',
        'frontdoor', 'firewall', 'bastionhost', 'privatedns',
        'networkwatcher', 'expressroute', 'publicipaddress',
        -- GCP
        'compute', 'networksecurity', 'networksecurity', 'dns',
        'certificatemanager', 'networktopology',
        -- OCI
        'core', 'loadbalancer', 'waas',
        -- AliCloud
        'slb', 'alb', 'vpc', 'nat', 'ddos'
    )
    OR domain = 'network_security_and_connectivity'
    OR domain = 'application_and_api_security'
)
AND (network_security IS NULL OR network_security::text IN ('null', '{}'));

-- ── Verify ────────────────────────────────────────────────────────────────────
SELECT
    provider,
    COUNT(*) FILTER (WHERE (iam_security     ->> 'applicable')::boolean = true) AS iam,
    COUNT(*) FILTER (WHERE (network_security ->> 'applicable')::boolean = true) AS net
FROM rule_metadata
GROUP BY provider
ORDER BY provider;

COMMIT;
