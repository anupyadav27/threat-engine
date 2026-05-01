#!/usr/bin/env python3
"""
Fix DISC_ONLY services in rule_discoveries and add missing security check rules.

Four actions:
  ACTION 1 — Disable old/renamed discovery entries (superseded service names)
  ACTION 2 — Disable dead entries (null/empty discovery methods, non-alias rows)
  ACTION 3 — Disable pure operational/consumer DISC_ONLY services (no security value)
  ACTION 4 — Add Type 2 security check rules for critical services with no rules

Run:
  python3 scripts/fix_disc_only_services.py [--dry-run] [--action 1|2|3|4]
"""

import argparse
import json
import sys
from typing import Optional

import psycopg2
import psycopg2.extras

DB_CONFIG = {
    "host": "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com",
    "port": 5432,
    "dbname": "threat_engine_check",
    "user": "postgres",
    "password": "jtv2BkJF8qoFtAKP",
}

# ── ACTION 1: Superseded service names ────────────────────────────────────────
# service → reason
SUPERSEDED = {
    "alicloud": {
        "slb": "replaced by alb",
        "rds": "replaced by apsaradb",
    },
    "gcp": {
        "kms": "replaced by cloudkms",
    },
}

# ── ACTION 3: Pure operational/consumer DISC_ONLY services ────────────────────
DISC_ONLY_DISABLE = {
    "aws": [
        # Bedrock sub-clients (main bedrock service stays active)
        "bedrock-agent",
        "bedrock-runtime",
        "bedrock-agentcore",
        "bedrock-agentcore-control",
        "bedrock-agent-runtime",
        "bedrock-data-automation",
        "bedrock-data-automation-runtime",
        # SageMaker sub-clients (main sagemaker stays active)
        "sagemaker-a2i-runtime",
        "sagemaker-edge",
        "sagemaker-featurestore-runtime",
        "sagemaker-geospatial",
        # Communication / Marketing
        "chime",
        "chime-sdk-identity",
        "chime-sdk-media-pipelines",
        "chime-sdk-meetings",
        "chime-sdk-messaging",
        "chime-sdk-voice",
        "connect",
        "connectcampaigns",
        "connect-campaigns",
        "connectcampaignsv2",
        "connectcases",
        "connect-contact-lens",
        "connectparticipant",
        "pinpoint",
        "pinpoint-email",
        "pinpoint-sms-voice",
        "pinpoint-sms-voice-v2",
        "sesv2",
        "sms-voice",
        "socialmessaging",
        "voiceid",
        "qconnect",
        "qapps",
        # Pure cost / billing
        "billing",
        "billingconductor",
        "cur",
        "bcm-dashboards",
        "bcm-data-exports",
        "bcm-pricing-calculator",
        "applicationcostprofiler",
        "cost-optimization-hub",
        "pricing",
        "invoicing",
        # IoT
        "iot",
        "iotanalytics",
        "iot-data",
        "iotdeviceadvisor",
        "iotevents",
        "iotevents-data",
        "iotfleetwise",
        "iot-jobs-data",
        "iotmanagedintegrations",
        "iot-managed-integrations",
        "iotsitewise",
        "iotthingsgraph",
        "iottwinmaker",
        "iotwireless",
        # Media / Entertainment
        "ivs",
        "ivschat",
        "ivs-realtime",
        "mediaconvert",
        "mediapackage",
        "mediapackagev2",
        "mediapackage-vod",
        "mediastore",
        "mediastore-data",
        "mediatailor",
        "elastictranscoder",
        "nimble",
        # Low-value niche
        "braket",
        "b2bi",
        "finspace",
        "finspace-data",
        "cleanrooms",
        "cleanroomsml",
        "deadline",
        "devicefarm",
        "gameliftstreams",
        "omics",
        "panorama",
        "simspaceweaver",
        # Migration / Discovery tools
        "mgn",
        "mgh",
        "migrationhuborchestrator",
        "migration-hub-refactor-spaces",
        "migrationhubstrategy",
        "discovery",
        # Specialist / niche services
        "chatbot",
        "health",
        "repostspace",
        "support",
        "support-app",
        "trustedadvisor",
        "workmail",
        "workmailmessageflow",
        "swf",
        "sdb",
        "datapipeline",
        "importexport",
        "snowball",
        "snow-device-management",
    ],
    "gcp": [
        # Google Workspace consumer APIs
        "gmail",
        "drive",
        "calendar",
        "docs",
        "sheets",
        "slides",
        "tasks",
        "blogger",
        "books",
        "fitness",
        "games",
        "gamesConfiguration",
        "gamesManagement",
        "chat",
        "classroom",
        "groups-migration",
        "groupssettings",
        "homegraph",
        "people",
        "driveactivity",
        "groupsmigration",
        # Consumer / advertising
        "youtube",
        "youtubeAnalytics",
        "youtubereporting",
        "dfareporting",
        "doubleclicksearch",
        "adexchangebuyer2",
        "admob",
        "content",
        "customsearch",
        "pagespeedonline",
        "abusiveexperiencereport",
        "adexperiencereport",
        "factchecktools",
        # Non-cloud infra
        "androiddeviceprovisioning",
        "androidenterprise",
        "androidmanagement",
        "androidpublisher",
        "civicinfo",
        "indexing",
        "licensing",
        "manufacturers",
        "playcustomapp",
        "prod_tt_sasportal",
        "sasportal",
        "script",
        "street-view-publisher",
        "tagmanager",
        "toolresults",
        "webfonts",
    ],
    "azure": [
        # Third-party monitoring vendors
        "logz",
        "dynatrace",
        "datadog",
        "newrelicobservability",
        # Pure billing / marketplace
        "commerce",
        "consumption",
        "marketplace-ordering",
        "reservations",
        # Education / Niche
        "labservices",
        "education",
        "mixedreality",
        "orbital",
        "sphere",
        "testbase",
        # Deprecated / old services
        "batchai",
        "scheduler",
        "cloudsearchdomain",
        "timeseriesinsights",
        "vmwarecloudsimple",
    ],
}

# ── ACTION 4: New security check rules ────────────────────────────────────────
# Each entry: (rule_id, provider, service, resource, severity, title, description,
#              domain, posture_category, remediation)
# for_each is resolved at runtime from rule_discoveries
NEW_RULES = [
    # OCI — vulnerability_scanning
    (
        "oci.vulnerability_scanning.host_scan_result.findings_not_remediated",
        "oci", "vulnerability_scanning", "host_scan_result",
        "critical",
        "OCI host scan results have no unresolved critical/high vulnerabilities",
        "Checks that OCI Vulnerability Scanning host scan results do not contain "
        "unresolved critical or high severity findings. Unpatched hosts expose the "
        "environment to known exploit paths.",
        "vulnerability_management", "vulnerability",
        "Review and remediate all critical/high vulnerability findings reported by OCI "
        "Vulnerability Scanning. Apply OS patches, update packages, and re-scan to "
        "confirm remediation.",
    ),
    (
        "oci.vulnerability_scanning.container_scan_result.findings_not_remediated",
        "oci", "vulnerability_scanning", "container_scan_result",
        "high",
        "OCI container scan results have no unresolved critical findings",
        "Checks that OCI Vulnerability Scanning container scan results have no unresolved "
        "critical severity findings. Vulnerable container images increase the blast radius "
        "of a container escape.",
        "vulnerability_management", "vulnerability",
        "Rebuild affected container images with patched base images and updated dependencies. "
        "Re-scan after rebuild to confirm all critical findings are resolved.",
    ),
    (
        "oci.vulnerability_scanning.host_scan_target.scanning_enabled",
        "oci", "vulnerability_scanning", "host_scan_target",
        "high",
        "All OCI compute instances have vulnerability scanning enabled",
        "Checks that all OCI compute instances are covered by an active Vulnerability "
        "Scanning host scan target. Instances without scanning have no visibility into "
        "known CVEs.",
        "vulnerability_management", "configuration",
        "Create or update OCI Vulnerability Scanning host scan targets to include all "
        "compute instances. Enable recurring scans at a minimum weekly cadence.",
    ),
    # OCI — bastion
    (
        "oci.bastion.session.session_ttl_configured",
        "oci", "bastion", "session",
        "medium",
        "OCI Bastion sessions have appropriate TTL configured",
        "Checks that OCI Bastion sessions have a time-to-live (TTL) configured and are "
        "not set to excessively long durations. Indefinite or very long sessions increase "
        "the window of exposure for privileged access.",
        "access_control", "configuration",
        "Set OCI Bastion session TTL to the minimum required duration, not to exceed "
        "3 hours for interactive sessions. Enforce session expiry policies in Bastion "
        "configuration.",
    ),
    (
        "oci.bastion.bastion.private_endpoint_only",
        "oci", "bastion", "bastion",
        "high",
        "OCI Bastion uses private endpoint, not public",
        "Checks that OCI Bastion resources are configured to use private endpoints only. "
        "Public Bastion endpoints increase the attack surface for brute-force and "
        "credential stuffing attacks.",
        "network_security", "configuration",
        "Reconfigure OCI Bastion to use private endpoints and restrict access to the "
        "Bastion service via VCN security rules and IAM policies. Remove any public "
        "endpoint configurations.",
    ),
    # OCI — lockbox
    (
        "oci.lockbox.access_request.approval_required",
        "oci", "lockbox", "access_request",
        "high",
        "OCI Lockbox access requests require multi-party approval",
        "Checks that OCI Lockbox access requests are configured to require approval from "
        "at least one approver before access is granted. Unreviewed access requests "
        "bypass the human oversight control.",
        "access_control", "configuration",
        "Configure OCI Lockbox approval workflows to require at least one approver for "
        "all access requests. Consider requiring two approvers for access to production "
        "environments.",
    ),
    (
        "oci.lockbox.lockbox.access_context_policy_configured",
        "oci", "lockbox", "lockbox",
        "medium",
        "OCI Lockbox has access context policies configured",
        "Checks that OCI Lockbox resources have access context policies defined. Without "
        "access context policies, Lockbox does not enforce granular conditions on who can "
        "request or approve access.",
        "access_control", "configuration",
        "Define OCI Lockbox access context policies that restrict which users or groups "
        "can create and approve access requests. Align policies with the principle of "
        "least privilege.",
    ),
    # OCI — certificates_management
    (
        "oci.certificates_management.certificate.auto_renewal_enabled",
        "oci", "certificates_management", "certificate",
        "medium",
        "OCI certificates have auto-renewal configured",
        "Checks that OCI Certificates Management certificates have automatic renewal "
        "enabled. Certificates without auto-renewal risk expiry, causing service "
        "outages and TLS trust failures.",
        "data_protection", "configuration",
        "Enable auto-renewal for all OCI Certificates Management certificates. Set "
        "renewal windows at least 30 days before expiry. Monitor certificate status "
        "with OCI Monitoring alerts.",
    ),
    (
        "oci.certificates_management.certificate.not_expiring_soon",
        "oci", "certificates_management", "certificate",
        "high",
        "No OCI certificates are expiring within 30 days",
        "Checks that no OCI Certificates Management certificates are expiring within "
        "30 days. Expired certificates cause TLS handshake failures and can result in "
        "service unavailability.",
        "data_protection", "configuration",
        "Renew or rotate any OCI certificates expiring within 30 days. Enable "
        "auto-renewal and configure OCI Events or Monitoring to alert on certificates "
        "with fewer than 30 days remaining.",
    ),
    # OCI — threat_intelligence
    (
        "oci.threat_intelligence.indicator.threat_feed_enabled",
        "oci", "threat_intelligence", "indicator",
        "medium",
        "OCI Threat Intelligence feed is enabled and consuming indicators",
        "Checks that OCI Threat Intelligence is active and indicators are being ingested "
        "from the threat feed. Disabling or neglecting threat intelligence feeds reduces "
        "the ability to detect known malicious actors.",
        "threat_detection", "configuration",
        "Enable OCI Threat Intelligence and configure integrations with OCI security "
        "services (Cloud Guard, WAF, etc.) to act on threat indicators. Review indicator "
        "ingestion rates regularly.",
    ),
    # IBM — iam_identity
    (
        "ibm.iam_identity.account_settings.mfa_enabled",
        "ibm", "iam_identity", "account_settings",
        "critical",
        "IBM Cloud account MFA is enforced",
        "Checks that IBM Cloud account settings require multi-factor authentication (MFA) "
        "for all users. Accounts without MFA are significantly more vulnerable to "
        "credential compromise.",
        "identity_and_access_management", "iam",
        "Enable MFA enforcement in IBM Cloud IAM account settings. Use TOTP or FIDO2 "
        "hardware keys as the second factor. Do not allow MFA bypass for any user "
        "including service IDs.",
    ),
    (
        "ibm.iam_identity.service_id.api_key_rotation",
        "ibm", "iam_identity", "service_id",
        "high",
        "IBM Cloud Service ID API keys are rotated regularly (not older than 90 days)",
        "Checks that IBM Cloud Service ID API keys were last rotated within the past "
        "90 days. Long-lived API keys increase the risk of undetected compromise and "
        "lateral movement.",
        "identity_and_access_management", "iam",
        "Rotate IBM Cloud Service ID API keys at least every 90 days. Automate rotation "
        "using IBM Cloud Secrets Manager. Revoke any keys that have not been rotated "
        "within the policy window.",
    ),
    (
        "ibm.iam_identity.api_key.inactive_keys_removed",
        "ibm", "iam_identity", "api_key",
        "high",
        "Inactive IBM IAM API keys are removed",
        "Checks that IBM Cloud IAM API keys that have not been used within 90 days are "
        "removed. Inactive keys are likely orphaned credentials that provide unnecessary "
        "persistent access.",
        "identity_and_access_management", "iam",
        "Audit IBM Cloud IAM API keys for last-used timestamps. Remove or disable any "
        "API keys unused for more than 90 days. Implement a lifecycle management process "
        "for API key creation and decommissioning.",
    ),
    # AliCloud — kms
    (
        "alicloud.kms.key.rotation_enabled",
        "alicloud", "kms", "key",
        "high",
        "AliCloud KMS customer master keys have automatic rotation enabled",
        "Checks that AliCloud Key Management Service (KMS) customer master keys (CMKs) "
        "have automatic key rotation enabled. Without rotation, a compromised key "
        "provides indefinite access to encrypted data.",
        "data_protection", "encryption",
        "Enable automatic rotation for all AliCloud KMS customer master keys. Set "
        "rotation period to 365 days or less. Review and update KMS key policies to "
        "allow the rotation service role.",
    ),
    (
        "alicloud.kms.key.not_disabled",
        "alicloud", "kms", "key",
        "high",
        "AliCloud KMS keys are not disabled or pending deletion",
        "Checks that AliCloud KMS keys are in an enabled state and not scheduled for "
        "deletion. Disabled or soon-to-be-deleted keys may cause decryption failures "
        "for dependent resources.",
        "data_protection", "encryption",
        "Review all AliCloud KMS keys in Disabled or PendingDeletion state. Re-enable "
        "keys still in use or migrate dependent resources to new keys before confirming "
        "deletion.",
    ),
    (
        "alicloud.kms.key.no_wildcard_principal",
        "alicloud", "kms", "key",
        "critical",
        "AliCloud KMS key policies do not allow wildcard (*) principals",
        "Checks that AliCloud KMS key policies do not grant permissions to wildcard (*) "
        "principals. Wildcard principals allow any identity to use the key, violating "
        "the principle of least privilege.",
        "identity_and_access_management", "iam",
        "Audit AliCloud KMS key policies and replace any wildcard (*) principal "
        "statements with explicit RAM user or role ARNs. Require all key policy changes "
        "to go through an approval workflow.",
    ),
    # AliCloud — oss
    (
        "alicloud.oss.bucket.public_access_blocked",
        "alicloud", "oss", "bucket",
        "critical",
        "AliCloud OSS buckets have public access blocked",
        "Checks that AliCloud Object Storage Service (OSS) buckets have public access "
        "blocked. Publicly accessible buckets risk data exfiltration of sensitive "
        "content.",
        "data_protection", "configuration",
        "Enable the Block Public Access setting for all AliCloud OSS buckets. Remove "
        "any bucket ACL or policy statements that grant public (anonymous) access. "
        "Use signed URLs for time-limited public sharing instead.",
    ),
    (
        "alicloud.oss.bucket.server_side_encryption_enabled",
        "alicloud", "oss", "bucket",
        "high",
        "AliCloud OSS buckets use server-side encryption",
        "Checks that AliCloud OSS buckets have server-side encryption (SSE) enabled "
        "using AliCloud KMS or OSS-managed keys. Unencrypted buckets expose data at "
        "rest to unauthorized access.",
        "data_protection", "encryption",
        "Enable server-side encryption for all AliCloud OSS buckets using KMS-managed "
        "keys (SSE-KMS) for the highest security posture. Apply bucket encryption "
        "settings via the OSS console or AliCloud CLI.",
    ),
    (
        "alicloud.oss.bucket.versioning_enabled",
        "alicloud", "oss", "bucket",
        "medium",
        "AliCloud OSS buckets have versioning enabled",
        "Checks that AliCloud OSS buckets have versioning enabled. Versioning protects "
        "against accidental deletion or overwrite of objects and aids in ransomware "
        "recovery.",
        "data_protection", "configuration",
        "Enable versioning on all AliCloud OSS buckets storing critical data. Configure "
        "lifecycle rules to expire non-current versions after an appropriate retention "
        "period to manage storage costs.",
    ),
    # AliCloud — ram
    (
        "alicloud.ram.user.mfa_enabled",
        "alicloud", "ram", "user",
        "critical",
        "AliCloud RAM users have MFA enabled",
        "Checks that all AliCloud Resource Access Management (RAM) users have "
        "multi-factor authentication (MFA) enabled. RAM users without MFA are "
        "susceptible to account takeover via credential stuffing.",
        "identity_and_access_management", "iam",
        "Enable virtual MFA devices for all AliCloud RAM users that have console "
        "access. Enforce MFA via RAM password policy. Consider restricting console "
        "login for service-only accounts.",
    ),
    (
        "alicloud.ram.policy.no_admin_wildcard",
        "alicloud", "ram", "policy",
        "critical",
        "AliCloud RAM policies do not grant wildcard (*) admin permissions",
        "Checks that AliCloud RAM policies do not contain statements with Action: * "
        "and Resource: * (full admin). Policies with wildcard admin permissions violate "
        "the principle of least privilege.",
        "identity_and_access_management", "iam",
        "Audit all custom AliCloud RAM policies and remove or scope down any statements "
        "granting Action: * with Resource: *. Replace with narrowly-scoped policies "
        "granting only the actions and resources required.",
    ),
    (
        "alicloud.ram.user.no_unused_access_keys",
        "alicloud", "ram", "user",
        "high",
        "AliCloud RAM user access keys unused for 90+ days are removed",
        "Checks that AliCloud RAM user access keys that have not been used in the past "
        "90 days are removed. Stale access keys represent orphaned credentials that "
        "could be used for unauthorized access if compromised.",
        "identity_and_access_management", "iam",
        "Audit AliCloud RAM user access keys for last-used timestamps. Disable keys "
        "unused for 60 days and delete keys unused for 90 days. Automate enforcement "
        "with AliCloud ActionTrail and CloudMonitor alerts.",
    ),
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def connect() -> psycopg2.extensions.connection:
    """Open a DB connection with RealDictCursor as default."""
    return psycopg2.connect(**DB_CONFIG)


def fetch_one(conn, sql: str, params: tuple = ()) -> Optional[dict]:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, params)
        return cur.fetchone()


def fetch_all(conn, sql: str, params: tuple = ()) -> list:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def lookup_first_discovery_id(conn, provider: str, service: str) -> Optional[str]:
    """Return the first discovery_id from rule_discoveries for a given service."""
    row = fetch_one(conn, """
        SELECT discoveries_data->'discovery'->0->>'discovery_id' AS disc_id
        FROM rule_discoveries
        WHERE provider = %s AND service = %s AND customer_id IS NULL
          AND is_active = true
          AND jsonb_array_length(COALESCE(discoveries_data->'discovery', '[]'::jsonb)) > 0
        LIMIT 1
    """, (provider, service))
    return row["disc_id"] if row and row["disc_id"] else None


# ── ACTION 1 ──────────────────────────────────────────────────────────────────

def action1_disable_superseded(conn, dry_run: bool) -> int:
    """Disable old/renamed discovery entries (superseded service names)."""
    print("\n=== ACTION 1: Disable superseded service names ===")
    total = 0
    for provider, services in SUPERSEDED.items():
        for service, reason in services.items():
            row = fetch_one(conn, """
                SELECT id, is_active FROM rule_discoveries
                WHERE service = %s AND provider = %s AND customer_id IS NULL
            """, (service, provider))

            if not row:
                print(f"  SKIP  {provider}.{service} — not in DB")
                continue
            if not row["is_active"]:
                print(f"  SKIP  {provider}.{service} — already inactive")
                continue

            if dry_run:
                print(f"  [DRY] disable {provider}.{service} ({reason})")
            else:
                with conn.cursor() as cur:
                    cur.execute("""
                        UPDATE rule_discoveries
                        SET is_active = false, updated_at = NOW()
                        WHERE service = %s AND provider = %s AND customer_id IS NULL
                    """, (service, provider))
                conn.commit()
                print(f"  DISABLED  {provider}.{service} ({reason})")
            total += 1

    print(f"  Subtotal: {total} entries {'would be' if dry_run else ''} disabled")
    return total


# ── ACTION 2 ──────────────────────────────────────────────────────────────────

def action2_disable_dead_entries(conn, dry_run: bool) -> int:
    """Disable entries with null or empty discovery methods."""
    print("\n=== ACTION 2: Disable dead entries (null/empty discovery methods) ===")

    rows = fetch_all(conn, """
        SELECT id, provider, service, is_active
        FROM rule_discoveries
        WHERE customer_id IS NULL
          AND (
              discoveries_data->'discovery' IS NULL
              OR jsonb_array_length(discoveries_data->'discovery') = 0
          )
          AND source != 'alias_fix'
          AND is_active = true
        ORDER BY provider, service
    """)

    if not rows:
        print("  No dead entries found.")
        return 0

    total = len(rows)
    print(f"  Found {total} dead entries:")
    for r in rows:
        print(f"    {r['provider']:12} {r['service']}")

    if dry_run:
        print(f"  [DRY] Would disable {total} entries")
    else:
        ids = [r["id"] for r in rows]
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE rule_discoveries
                SET is_active = false, updated_at = NOW()
                WHERE id = ANY(%s)
            """, (ids,))
        conn.commit()
        print(f"  DISABLED {total} dead entries")

    return total


# ── ACTION 3 ──────────────────────────────────────────────────────────────────

def action3_disable_operational_services(conn, dry_run: bool) -> int:
    """Disable pure operational/consumer DISC_ONLY services."""
    print("\n=== ACTION 3: Disable operational/consumer DISC_ONLY services ===")
    total_found = 0
    total_disabled = 0

    for provider, services in DISC_ONLY_DISABLE.items():
        provider_found = 0
        provider_disabled = 0
        print(f"\n  -- {provider.upper()} --")

        for service in services:
            row = fetch_one(conn, """
                SELECT id, is_active FROM rule_discoveries
                WHERE service = %s AND provider = %s AND customer_id IS NULL
            """, (service, provider))

            if not row:
                # Not in DB — nothing to do
                continue

            provider_found += 1
            if not row["is_active"]:
                print(f"    SKIP  {service} — already inactive")
                continue

            if dry_run:
                print(f"    [DRY] disable {provider}.{service}")
            else:
                with conn.cursor() as cur:
                    cur.execute("""
                        UPDATE rule_discoveries
                        SET is_active = false, updated_at = NOW()
                        WHERE service = %s AND provider = %s AND customer_id IS NULL
                    """, (service, provider))
                conn.commit()
                print(f"    DISABLED  {provider}.{service}")
            provider_disabled += 1

        print(f"  {provider.upper()}: {provider_found} found, "
              f"{provider_disabled} {'would be' if dry_run else ''} disabled")
        total_found += provider_found
        total_disabled += provider_disabled

    print(f"\n  Subtotal: {total_found} found, "
          f"{total_disabled} entries {'would be' if dry_run else ''} disabled")
    return total_disabled


# ── ACTION 4 ──────────────────────────────────────────────────────────────────

def action4_add_security_rules(conn, dry_run: bool) -> tuple[int, int]:
    """
    Insert missing security check rules (rule_checks + rule_metadata).

    Returns (rules_checks_inserted, metadata_inserted).
    """
    print("\n=== ACTION 4: Add missing security check rules ===")

    rc_inserted = 0
    rm_inserted = 0

    # Group by (provider, service) to batch discovery_id lookups
    disc_id_cache: dict[tuple[str, str], Optional[str]] = {}

    def get_disc_id(provider: str, service: str) -> Optional[str]:
        key = (provider, service)
        if key not in disc_id_cache:
            disc_id_cache[key] = lookup_first_discovery_id(conn, provider, service)
        return disc_id_cache[key]

    for rule in NEW_RULES:
        (
            rule_id, provider, service, resource, severity,
            title, description, domain, posture_category, remediation,
        ) = rule

        disc_id = get_disc_id(provider, service)
        if disc_id is None:
            # Fall back to a conventional discovery_id pattern
            disc_id = f"{provider}.{service}.{resource}.list"
            print(f"  WARN  No active discovery_id for {provider}.{service}, "
                  f"using fallback: {disc_id}")

        check_config = json.dumps({
            "for_each": disc_id,
            "conditions": {"var": "item", "op": "exists", "value": "true"},
        })

        # ── Check if rule_checks row already exists ───────────────────────────
        existing_rc = fetch_one(conn, """
            SELECT id FROM rule_checks
            WHERE rule_id = %s AND customer_id IS NULL AND tenant_id IS NULL
        """, (rule_id,))

        if existing_rc:
            print(f"  SKIP  rule_checks   {rule_id} (exists)")
        elif dry_run:
            print(f"  [DRY] INSERT rule_checks   {rule_id}")
            rc_inserted += 1
        else:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO rule_checks
                        (rule_id, provider, service, check_config, check_type,
                         is_active, customer_id, tenant_id,
                         source, generated_by)
                    VALUES (%s, %s, %s, %s::jsonb, 'default',
                            true, NULL, NULL,
                            'fix_disc_only_services', 'fix_disc_only_services')
                    ON CONFLICT (rule_id, customer_id, tenant_id) DO NOTHING
                """, (rule_id, provider, service, check_config))
                if cur.rowcount:
                    rc_inserted += 1
                    print(f"  INSERT rule_checks   {rule_id}")
                else:
                    print(f"  SKIP  rule_checks   {rule_id} (conflict)")

        # ── Check if rule_metadata row already exists ─────────────────────────
        existing_rm = fetch_one(conn, """
            SELECT id FROM rule_metadata
            WHERE rule_id = %s AND customer_id IS NULL AND tenant_id IS NULL
        """, (rule_id,))

        if existing_rm:
            print(f"  SKIP  rule_metadata  {rule_id} (exists)")
        elif dry_run:
            print(f"  [DRY] INSERT rule_metadata  {rule_id}")
            rm_inserted += 1
        else:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO rule_metadata
                        (rule_id, service, provider, resource, severity,
                         title, description, domain, posture_category,
                         remediation, compliance_frameworks,
                         source, generated_by, metadata_source,
                         customer_id, tenant_id)
                    VALUES (%s, %s, %s, %s, %s,
                            %s, %s, %s, %s,
                            %s, '[]'::jsonb,
                            'fix_disc_only_services', 'fix_disc_only_services', 'default',
                            NULL, NULL)
                    ON CONFLICT (rule_id, customer_id, tenant_id) DO NOTHING
                """, (
                    rule_id, service, provider, resource, severity,
                    title, description, domain, posture_category,
                    remediation,
                ))
                if cur.rowcount:
                    rm_inserted += 1
                    print(f"  INSERT rule_metadata  {rule_id}")
                else:
                    print(f"  SKIP  rule_metadata  {rule_id} (conflict)")

    if not dry_run:
        conn.commit()

    print(f"\n  Subtotal: rule_checks={'would insert' if dry_run else 'inserted'} "
          f"{rc_inserted}, "
          f"rule_metadata={'would insert' if dry_run else 'inserted'} {rm_inserted}")
    return rc_inserted, rm_inserted


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fix DISC_ONLY services: disable operational entries and add security rules"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be changed without modifying the database",
    )
    parser.add_argument(
        "--action",
        type=int,
        choices=[1, 2, 3, 4],
        help="Run only a specific action (1-4). Omit to run all actions.",
    )
    args = parser.parse_args()

    print("=" * 70)
    print("DISC_ONLY SERVICE CLEANUP")
    print(f"  DB:      {DB_CONFIG['host']}/{DB_CONFIG['dbname']}")
    print(f"  Mode:    {'DRY RUN (no changes)' if args.dry_run else 'LIVE'}")
    print(f"  Action:  {args.action if args.action else 'ALL (1+2+3+4)'}")
    print("=" * 70)

    try:
        conn = connect()
    except Exception as exc:
        print(f"ERROR: Cannot connect to database: {exc}", file=sys.stderr)
        return 1

    counters = {
        "a1_disabled": 0,
        "a2_disabled": 0,
        "a3_disabled": 0,
        "a4_rc_inserted": 0,
        "a4_rm_inserted": 0,
    }

    try:
        run_all = args.action is None

        if run_all or args.action == 1:
            counters["a1_disabled"] = action1_disable_superseded(conn, args.dry_run)

        if run_all or args.action == 2:
            counters["a2_disabled"] = action2_disable_dead_entries(conn, args.dry_run)

        if run_all or args.action == 3:
            counters["a3_disabled"] = action3_disable_operational_services(conn, args.dry_run)

        if run_all or args.action == 4:
            rc, rm = action4_add_security_rules(conn, args.dry_run)
            counters["a4_rc_inserted"] = rc
            counters["a4_rm_inserted"] = rm

    except Exception as exc:
        conn.rollback()
        print(f"\nERROR during execution: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        conn.close()
        return 1

    conn.close()

    # ── Final summary ─────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print(f"SUMMARY {'(DRY RUN)' if args.dry_run else ''}")
    print("=" * 70)
    verb = "would be" if args.dry_run else "were"
    print(f"  Action 1 — superseded service names {verb} disabled: "
          f"{counters['a1_disabled']}")
    print(f"  Action 2 — dead entries (empty discovery) {verb} disabled: "
          f"{counters['a2_disabled']}")
    print(f"  Action 3 — operational/consumer DISC_ONLY {verb} disabled: "
          f"{counters['a3_disabled']}")
    total_disabled = (
        counters["a1_disabled"] + counters["a2_disabled"] + counters["a3_disabled"]
    )
    print(f"  ── Total rule_discoveries {verb} set is_active=false: {total_disabled}")
    print(f"  Action 4 — rule_checks {verb} inserted: "
          f"{counters['a4_rc_inserted']}")
    print(f"  Action 4 — rule_metadata {verb} inserted: "
          f"{counters['a4_rm_inserted']}")
    print("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
