-- ============================================================================
-- Migration 005: Add network_security and action_category columns to rule_metadata
--
-- network_security — network engine scope column (same pattern as 003)
--   WHERE (network_security ->> 'applicable')::boolean = true
--
-- action_category — CRUD-style action class (create/read/update/delete/list/auth)
--   Used by network engine and CIEM log rules.
-- ============================================================================

BEGIN;

-- ── Schema ────────────────────────────────────────────────────────────────────
ALTER TABLE rule_metadata ADD COLUMN IF NOT EXISTS network_security JSONB DEFAULT '{}'::jsonb;
ALTER TABLE rule_metadata ADD COLUMN IF NOT EXISTS action_category  VARCHAR(50);

-- ── Network: domain-based ─────────────────────────────────────────────────────
UPDATE rule_metadata
SET network_security = '{"applicable": true}'::jsonb
WHERE domain = 'network_security_and_connectivity'
  AND (network_security IS NULL OR network_security::text IN ('null', '{}'));

-- ── Network: service-based (all providers) ────────────────────────────────────
UPDATE rule_metadata
SET network_security = '{"applicable": true}'::jsonb
WHERE service IN (
    -- AWS
    'vpc', 'ec2', 'waf', 'wafv2', 'shield', 'cloudfront', 'route53',
    'elb', 'elbv2', 'alb', 'nlb', 'globalaccelerator', 'apigateway',
    'apigatewayv2', 'network-firewall', 'networkfirewall', 'vpn',
    'directconnect', 'transit-gateway', 'transitgateway',
    -- Azure
    'virtualnetwork', 'networksecuritygroup', 'applicationgateway',
    'firewall', 'loadbalancer', 'publicipaddress', 'frontdoor',
    'expressroute', 'networkwatcher', 'ddosprotection',
    -- GCP
    'compute',       -- covers VPC, firewall rules, load balancers
    'dns', 'armor',  -- Cloud Armor = WAF
    -- OCI
    'core',          -- OCI VCN, subnets, security lists
    'loadbalancer',
    -- AliCloud
    'slb', 'ecs_vpc', 'nat_gateway',
    -- K8s
    'networkpolicy', 'ingress', 'service'
)
AND (network_security IS NULL OR network_security::text IN ('null', '{}'));

-- ── action_category: backfill from existing threat_tags/rule_id patterns ──────
-- Covers CIEM log rules that already have check_type populated
UPDATE rule_metadata
SET action_category = CASE
    WHEN rule_id LIKE '%.create%'  OR rule_id LIKE '%.add%'    OR rule_id LIKE '%.put%'
         OR rule_id LIKE '%.launch%' OR rule_id LIKE '%.run%'  THEN 'create'
    WHEN rule_id LIKE '%.delete%'  OR rule_id LIKE '%.remove%' OR rule_id LIKE '%.terminate%'
         OR rule_id LIKE '%.destroy%'                           THEN 'delete'
    WHEN rule_id LIKE '%.update%'  OR rule_id LIKE '%.modify%' OR rule_id LIKE '%.patch%'
         OR rule_id LIKE '%.set%'  OR rule_id LIKE '%.change%' THEN 'update'
    WHEN rule_id LIKE '%.list%'    OR rule_id LIKE '%.describe%' OR rule_id LIKE '%.get%'
         OR rule_id LIKE '%.read%' OR rule_id LIKE '%.query%'  THEN 'read'
    WHEN rule_id LIKE '%.login%'   OR rule_id LIKE '%.auth%'   OR rule_id LIKE '%.assume%'
         OR rule_id LIKE '%.sign%' OR rule_id LIKE '%.token%'  THEN 'auth'
    ELSE NULL
END
WHERE action_category IS NULL;

-- ── Verify ────────────────────────────────────────────────────────────────────
SELECT
    provider,
    COUNT(*) FILTER (WHERE (network_security ->> 'applicable')::boolean = true) AS network,
    COUNT(*) FILTER (WHERE action_category IS NOT NULL)                          AS with_action_cat
FROM rule_metadata
GROUP BY provider
ORDER BY provider;

COMMIT;
