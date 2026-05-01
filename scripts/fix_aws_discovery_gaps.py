#!/usr/bin/env python3
"""
fix_aws_discovery_gaps.py

Fixes missing discovery_id entries in rule_discoveries so that
rule_checks.check_config->>'for_each' values can be resolved at scan time.

Two types of fixes:
  1. Activate inactive services that already have the needed discovery_ids.
  2. Insert missing discovery entries (new discovery_id records) into existing rows.
"""

import json
import sys
from typing import Any

import psycopg2
import psycopg2.extras

DB_CONFIG = dict(
    host="postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com",
    port=5432,
    dbname="threat_engine_check",
    user="postgres",
    password="jtv2BkJF8qoFtAKP",
)

# ---------------------------------------------------------------------------
# New discovery entries to add.  Each dict is a full discovery block that
# will be appended to the service's discoveries_data->'discovery' array.
# The `_service` key is used to route the entry to the correct row.
# ---------------------------------------------------------------------------
NEW_ENTRIES: list[dict[str, Any]] = [
    # ── wafv2: alias list_web_acls → list_web_ac_ls ──
    {
        "_service": "wafv2",
        "discovery_id": "aws.wafv2.list_web_acls",
        "calls": [{"action": "list_web_ac_ls", "params": {"Limit": 100}, "save_as": "response", "on_error": "continue"}],
        "emit": {"as": "item", "items_for": "{{ response.WebACLs }}", "item": {"Id": "{{ item.Id }}", "ARN": "{{ item.ARN }}", "Name": "{{ item.Name }}", "LockToken": "{{ item.LockToken }}", "Description": "{{ item.Description }}"}},
    },
    # ── waf: alias list_web_acls → list_web_ac_ls ──
    {
        "_service": "waf",
        "discovery_id": "aws.waf.list_web_acls",
        "calls": [{"action": "list_web_ac_ls", "save_as": "response", "on_error": "continue"}],
        "emit": {"as": "item", "items_for": "{{ response.WebACLs }}", "item": {"Name": "{{ item.Name }}", "WebACLId": "{{ item.WebACLId }}"}},
    },
    # ── sagemaker: list_algorithms ──
    {
        "_service": "sagemaker",
        "discovery_id": "aws.sagemaker.list_algorithms",
        "calls": [{"action": "list_algorithms", "save_as": "response", "on_error": "continue"}],
        "emit": {"as": "item", "items_for": "{{ response.AlgorithmSummaryList }}", "item": {"AlgorithmArn": "{{ item.AlgorithmArn }}", "AlgorithmName": "{{ item.AlgorithmName }}", "AlgorithmStatus": "{{ item.AlgorithmStatus }}", "CreationTime": "{{ item.CreationTime }}"}},
    },
    # ── sagemaker: list_auto_m_l_jobs alias for list_auto_ml_jobs ──
    {
        "_service": "sagemaker",
        "discovery_id": "aws.sagemaker.list_auto_m_l_jobs",
        "calls": [{"action": "list_auto_ml_jobs", "save_as": "response", "on_error": "continue"}],
        "emit": {"as": "item", "items_for": "{{ response.AutoMLJobSummaries }}", "item": {"AutoMLJobArn": "{{ item.AutoMLJobArn }}", "AutoMLJobName": "{{ item.AutoMLJobName }}", "AutoMLJobStatus": "{{ item.AutoMLJobStatus }}", "CreationTime": "{{ item.CreationTime }}"}},
    },
    # ── sagemaker: list_artifacts ──
    {
        "_service": "sagemaker",
        "discovery_id": "aws.sagemaker.list_artifacts",
        "calls": [{"action": "list_artifacts", "save_as": "response", "on_error": "continue"}],
        "emit": {"as": "item", "items_for": "{{ response.ArtifactSummaries }}", "item": {"ArtifactArn": "{{ item.ArtifactArn }}", "ArtifactName": "{{ item.ArtifactName }}", "ArtifactType": "{{ item.ArtifactType }}", "CreationTime": "{{ item.CreationTime }}", "LastModifiedTime": "{{ item.LastModifiedTime }}"}},
    },
    # ── sagemaker: list_experiments ──
    {
        "_service": "sagemaker",
        "discovery_id": "aws.sagemaker.list_experiments",
        "calls": [{"action": "list_experiments", "save_as": "response", "on_error": "continue"}],
        "emit": {"as": "item", "items_for": "{{ response.ExperimentSummaries }}", "item": {"ExperimentArn": "{{ item.ExperimentArn }}", "ExperimentName": "{{ item.ExperimentName }}", "CreationTime": "{{ item.CreationTime }}", "LastModifiedTime": "{{ item.LastModifiedTime }}"}},
    },
    # ── identitycenter: list_users ──
    {
        "_service": "identitycenter",
        "discovery_id": "aws.identitycenter.list_users",
        "calls": [{"action": "list_users", "save_as": "response", "on_error": "continue"}],
        "emit": {"as": "item", "items_for": "{{ response.Users }}", "item": {"UserId": "{{ item.UserId }}", "UserName": "{{ item.UserName }}", "DisplayName": "{{ item.DisplayName }}", "Emails": "{{ item.Emails }}"}},
    },
    # ── identitycenter: list_groups ──
    {
        "_service": "identitycenter",
        "discovery_id": "aws.identitycenter.list_groups",
        "calls": [{"action": "list_groups", "save_as": "response", "on_error": "continue"}],
        "emit": {"as": "item", "items_for": "{{ response.Groups }}", "item": {"GroupId": "{{ item.GroupId }}", "DisplayName": "{{ item.DisplayName }}", "Description": "{{ item.Description }}"}},
    },
    # ── identitycenter: list_permission_sets ──
    {
        "_service": "identitycenter",
        "discovery_id": "aws.identitycenter.list_permission_sets",
        "calls": [{"action": "list_permission_sets", "save_as": "response", "on_error": "continue"}],
        "emit": {"as": "item", "items_for": "{{ response.PermissionSets }}", "item": {"PermissionSetArn": "{{ item }}"}},
    },
    # ── identitycenter: list_permission_sets_provisioned_to_account ──
    {
        "_service": "identitycenter",
        "discovery_id": "aws.identitycenter.list_permission_sets_provisioned_to_account",
        "calls": [{"action": "list_permission_sets_provisioned_to_account", "save_as": "response", "on_error": "continue"}],
        "emit": {"as": "item", "items_for": "{{ response.PermissionSets }}", "item": {"PermissionSetArn": "{{ item }}"}},
    },
    # ── identitycenter: describe_permission_set ──
    {
        "_service": "identitycenter",
        "discovery_id": "aws.identitycenter.describe_permission_set",
        "calls": [{"action": "describe_permission_set", "save_as": "response", "on_error": "continue"}],
        "emit": {"as": "item", "items_for": "{{ response.PermissionSet }}", "item": {"PermissionSetArn": "{{ item.PermissionSetArn }}", "Name": "{{ item.Name }}", "Description": "{{ item.Description }}", "SessionDuration": "{{ item.SessionDuration }}"}},
    },
    # ── glue: get_column_statistics_task_run ──
    {
        "_service": "glue",
        "discovery_id": "aws.glue.get_column_statistics_task_run",
        "calls": [{"action": "get_column_statistics_task_run", "save_as": "response", "on_error": "continue"}],
        "emit": {"as": "item", "items_for": "{{ response.ColumnStatisticsTaskRun }}", "item": {"ColumnStatisticsTaskRunId": "{{ item.ColumnStatisticsTaskRunId }}", "Status": "{{ item.Status }}", "CatalogID": "{{ item.CatalogID }}"}},
    },
    # ── eks: describe_addon ──
    {
        "_service": "eks",
        "discovery_id": "aws.eks.describe_addon",
        "for_each": "aws.eks.list_addons",
        "calls": [{"action": "describe_addon", "params": {"clusterName": "{{ item.clusterName }}", "addonName": "{{ item.addonName }}"}, "save_as": "response", "on_error": "continue"}],
        "emit": {"as": "item", "items_for": "{{ response.addon }}", "item": {"addonArn": "{{ item.addonArn }}", "addonName": "{{ item.addonName }}", "clusterName": "{{ item.clusterName }}", "status": "{{ item.status }}", "addonVersion": "{{ item.addonVersion }}"}},
    },
    # ── ssm: describe_automation_executions ──
    {
        "_service": "ssm",
        "discovery_id": "aws.ssm.describe_automation_executions",
        "calls": [{"action": "describe_automation_executions", "save_as": "response", "on_error": "continue"}],
        "emit": {"as": "item", "items_for": "{{ response.AutomationExecutionMetadataList }}", "item": {"AutomationExecutionId": "{{ item.AutomationExecutionId }}", "AutomationExecutionStatus": "{{ item.AutomationExecutionStatus }}", "DocumentName": "{{ item.DocumentName }}", "ExecutionStartTime": "{{ item.ExecutionStartTime }}"}},
    },
    # ── inspector: list_assessment_runs (needed as parent for describe_assessment_runs) ──
    {
        "_service": "inspector",
        "discovery_id": "aws.inspector.list_assessment_runs",
        "calls": [{"action": "list_assessment_runs", "save_as": "response", "on_error": "continue"}],
        "emit": {"as": "item", "items_for": "{{ response.assessmentRunArns }}", "item": {"assessmentRunArn": "{{ item }}"}},
    },
    # ── inspector: describe_assessment_runs ──
    {
        "_service": "inspector",
        "discovery_id": "aws.inspector.describe_assessment_runs",
        "for_each": "aws.inspector.list_assessment_runs",
        "calls": [{"action": "describe_assessment_runs", "params": {"assessmentRunArns": "{{ item.assessmentRunArns }}"}, "save_as": "response", "on_error": "continue"}],
        "emit": {"as": "item", "items_for": "{{ response.assessmentRuns }}", "item": {"arn": "{{ item.arn }}", "name": "{{ item.name }}", "assessmentTemplateArn": "{{ item.assessmentTemplateArn }}", "state": "{{ item.state }}"}},
    },
    # ── sso: list_permission_sets ──
    {
        "_service": "sso",
        "discovery_id": "aws.sso.list_permission_sets",
        "calls": [{"action": "list_permission_sets", "save_as": "response", "on_error": "continue"}],
        "emit": {"as": "item", "items_for": "{{ response.PermissionSets }}", "item": {"PermissionSetArn": "{{ item }}"}},
    },
    # ── account: get_alternate_contact_security ──
    {
        "_service": "account",
        "discovery_id": "aws.account.get_alternate_contact_security",
        "calls": [{"action": "get_alternate_contact", "params": {"AlternateContactType": "SECURITY"}, "save_as": "response", "on_error": "continue"}],
        "emit": {"as": "item", "items_for": "{{ response.AlternateContact }}", "item": {"Name": "{{ item.Name }}", "AlternateContactType": "{{ item.AlternateContactType }}", "EmailAddress": "{{ item.EmailAddress }}", "PhoneNumber": "{{ item.PhoneNumber }}"}},
    },
    # ── cloudwatch: describe_composite_alarms ──
    {
        "_service": "cloudwatch",
        "discovery_id": "aws.cloudwatch.describe_composite_alarms",
        "calls": [{"action": "describe_alarms", "params": {"AlarmTypes": ["CompositeAlarm"]}, "save_as": "response", "on_error": "continue"}],
        "emit": {"as": "item", "items_for": "{{ response.CompositeAlarms }}", "item": {"AlarmArn": "{{ item.AlarmArn }}", "AlarmName": "{{ item.AlarmName }}", "AlarmDescription": "{{ item.AlarmDescription }}", "StateValue": "{{ item.StateValue }}"}},
    },
    # ── iam: list_s_a_m_l_providers (alias for list_saml_providers) ──
    {
        "_service": "iam",
        "discovery_id": "aws.iam.list_s_a_m_l_providers",
        "calls": [{"action": "list_saml_providers", "save_as": "response", "on_error": "continue"}],
        "emit": {"as": "item", "items_for": "{{ response.SAMLProviderList }}", "item": {"Arn": "{{ item.Arn }}", "CreateDate": "{{ item.CreateDate }}", "ValidUntil": "{{ item.ValidUntil }}"}},
    },
    # ── iam: get_key_rotation_status ──
    {
        "_service": "iam",
        "discovery_id": "aws.iam.get_key_rotation_status",
        "calls": [{"action": "get_access_key_last_used", "save_as": "response", "on_error": "continue"}],
        "emit": {"as": "item", "items_for": "{{ response.AccessKeyLastUsed }}", "item": {"AccessKeyId": "{{ item.AccessKeyId }}", "LastUsedDate": "{{ item.LastUsedDate }}", "ServiceName": "{{ item.ServiceName }}", "Region": "{{ item.Region }}"}},
    },
    # ── networkfirewall: describe_firewalls (alias for list_firewalls) ──
    {
        "_service": "networkfirewall",
        "discovery_id": "aws.networkfirewall.describe_firewalls",
        "calls": [{"action": "list_firewalls", "save_as": "response", "on_error": "continue"}],
        "emit": {"as": "item", "items_for": "{{ response.Firewalls }}", "item": {"FirewallArn": "{{ item.FirewallArn }}", "FirewallName": "{{ item.FirewallName }}"}},
    },
    # ── redshift: describe_event_categories ──
    {
        "_service": "redshift",
        "discovery_id": "aws.redshift.describe_event_categories",
        "calls": [{"action": "describe_event_categories", "save_as": "response", "on_error": "continue"}],
        "emit": {"as": "item", "items_for": "{{ response.EventCategoriesMapList }}", "item": {"SourceType": "{{ item.SourceType }}", "Events": "{{ item.Events }}"}},
    },
    # ── codebuild: batch_get_projects ──
    {
        "_service": "codebuild",
        "discovery_id": "aws.codebuild.batch_get_projects",
        "for_each": "aws.codebuild.list_projects",
        "calls": [{"action": "batch_get_projects", "params": {"names": "{{ item.projects }}"}, "save_as": "response", "on_error": "continue"}],
        "emit": {"as": "item", "items_for": "{{ response.projects }}", "item": {"arn": "{{ item.arn }}", "name": "{{ item.name }}", "description": "{{ item.description }}", "created": "{{ item.created }}", "environment": "{{ item.environment }}", "logsConfig": "{{ item.logsConfig }}", "encryptionKey": "{{ item.encryptionKey }}"}},
    },
    # ── elasticbeanstalk: describe_configuration_settings_for_environment ──
    {
        "_service": "elasticbeanstalk",
        "discovery_id": "aws.elasticbeanstalk.describe_configuration_settings_for_environment",
        "for_each": "aws.elasticbeanstalk.describe_environments",
        "calls": [{"action": "describe_configuration_settings", "params": {"ApplicationName": "{{ item.ApplicationName }}", "EnvironmentName": "{{ item.EnvironmentName }}"}, "save_as": "response", "on_error": "continue"}],
        "emit": {"as": "item", "items_for": "{{ response.ConfigurationSettings }}", "item": {"ApplicationName": "{{ item.ApplicationName }}", "EnvironmentName": "{{ item.EnvironmentName }}", "OptionSettings": "{{ item.OptionSettings }}", "DateCreated": "{{ item.DateCreated }}", "DateUpdated": "{{ item.DateUpdated }}"}},
    },
]

# Services that are currently is_active=False but already contain all needed
# discovery_ids — they just need to be re-activated.
SERVICES_TO_ACTIVATE = [
    "backup",
    "elb",
    "config",
    "autoscaling",
    "bedrock",
    "ce",
    "kafka",
    "savingsplans",
    "timestream-query",
    "keyspaces",
    "mq",
    "elasticbeanstalk",
]


def get_existing_discovery_ids(cur, service: str) -> set[str]:
    cur.execute(
        """
        SELECT d->>'discovery_id'
        FROM rule_discoveries rd,
             jsonb_array_elements(rd.discoveries_data->'discovery') d
        WHERE rd.service = %s AND rd.provider = 'aws'
        """,
        (service,),
    )
    return {row[0] for row in cur.fetchall()}


def activate_services(cur, services: list[str]) -> int:
    activated = 0
    for svc in services:
        cur.execute(
            "UPDATE rule_discoveries SET is_active = true, updated_at = NOW() WHERE service = %s AND provider = 'aws' AND is_active = false",
            (svc,),
        )
        if cur.rowcount > 0:
            print(f"  ACTIVATED: {svc}")
            activated += cur.rowcount
    return activated


def add_missing_entries(cur, entries: list[dict]) -> int:
    added = 0
    skipped = 0

    # Group by service
    by_service: dict[str, list[dict]] = {}
    for entry in entries:
        svc = entry["_service"]
        by_service.setdefault(svc, []).append(entry)

    for svc, svc_entries in by_service.items():
        existing = get_existing_discovery_ids(cur, svc)

        new_for_svc = []
        for entry in svc_entries:
            did = entry["discovery_id"]
            if did in existing:
                print(f"  SKIP (already exists): {did}")
                skipped += 1
                continue
            # Remove internal routing key before inserting
            clean = {k: v for k, v in entry.items() if not k.startswith("_")}
            new_for_svc.append(clean)
            print(f"  ADD: {did}")
            added += 1

        if not new_for_svc:
            continue

        # Append to the discovery array for this service
        new_jsonb = json.dumps(new_for_svc)
        cur.execute(
            """
            UPDATE rule_discoveries
            SET discoveries_data = jsonb_set(
                discoveries_data,
                '{discovery}',
                COALESCE(discoveries_data->'discovery', '[]'::jsonb) || %s::jsonb
            ),
            updated_at = NOW()
            WHERE service = %s AND provider = 'aws'
            """,
            (new_jsonb, svc),
        )
        if cur.rowcount == 0:
            print(f"  WARNING: no row found for service={svc}, skipping insert")
            added -= len(new_for_svc)

    return added


def verify(cur) -> int:
    cur.execute(
        """
        SELECT COUNT(DISTINCT rc.check_config->>'for_each')
        FROM rule_checks rc
        JOIN rule_metadata rm ON rc.rule_id = rm.rule_id
        WHERE rm.provider = 'aws'
          AND rc.is_active = true
          AND NOT EXISTS (
              SELECT 1
              FROM rule_discoveries rd,
                   jsonb_array_elements(rd.discoveries_data->'discovery') d
              WHERE rd.provider = 'aws'
                AND rd.is_active = true
                AND d->>'discovery_id' = rc.check_config->>'for_each'
          )
          AND rc.check_config->>'for_each' != 'log_events'
          AND rc.check_config->>'for_each' IS NOT NULL
        """
    )
    row = cur.fetchone()
    return row[0] if row else -1


def count_aligned_rules(cur) -> int:
    cur.execute(
        """
        SELECT COUNT(*)
        FROM rule_checks rc
        JOIN rule_metadata rm ON rc.rule_id = rm.rule_id
        WHERE rm.provider = 'aws'
          AND rc.is_active = true
          AND rc.check_config->>'for_each' IS NOT NULL
          AND rc.check_config->>'for_each' != 'log_events'
          AND EXISTS (
              SELECT 1
              FROM rule_discoveries rd,
                   jsonb_array_elements(rd.discoveries_data->'discovery') d
              WHERE rd.provider = 'aws'
                AND rd.is_active = true
                AND d->>'discovery_id' = rc.check_config->>'for_each'
          )
        """
    )
    row = cur.fetchone()
    return row[0] if row else 0


def main() -> None:
    print("Connecting to DB ...")
    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = False

    try:
        with conn.cursor() as cur:
            # Pre-fix state
            missing_before = verify(cur)
            aligned_before = count_aligned_rules(cur)
            print(f"\nBefore fix: {missing_before} unresolved for_each distinct values, {aligned_before} aligned rules")

            print("\n── Step 1: Activating inactive services ──")
            activated = activate_services(cur, SERVICES_TO_ACTIVATE)

            print("\n── Step 2: Adding missing discovery entries ──")
            added = add_missing_entries(cur, NEW_ENTRIES)

            # Post-fix state (before commit so we can verify in same txn)
            missing_after = verify(cur)
            aligned_after = count_aligned_rules(cur)

            print(f"\n── Results ──")
            print(f"  Services activated:          {activated}")
            print(f"  Discovery entries added:     {added}")
            print(f"  Unresolved for_each values:  {missing_before} → {missing_after}")
            print(f"  Aligned rules:               {aligned_before} → {aligned_after}")

            if missing_after == 0:
                print("\n  All for_each values resolved.")
            else:
                print(f"\n  WARNING: {missing_after} for_each values still unresolved.")
                # Show which ones
                cur.execute(
                    """
                    SELECT DISTINCT rc.check_config->>'for_each', COUNT(*) as rule_count
                    FROM rule_checks rc
                    JOIN rule_metadata rm ON rc.rule_id = rm.rule_id
                    WHERE rm.provider = 'aws'
                      AND rc.is_active = true
                      AND NOT EXISTS (
                          SELECT 1
                          FROM rule_discoveries rd,
                               jsonb_array_elements(rd.discoveries_data->'discovery') d
                          WHERE rd.provider = 'aws'
                            AND rd.is_active = true
                            AND d->>'discovery_id' = rc.check_config->>'for_each'
                      )
                      AND rc.check_config->>'for_each' != 'log_events'
                      AND rc.check_config->>'for_each' IS NOT NULL
                    GROUP BY rc.check_config->>'for_each'
                    ORDER BY rule_count DESC
                    """
                )
                for row in cur.fetchall():
                    print(f"    STILL MISSING: {row[0]} ({row[1]} rules)")

        conn.commit()
        print("\nCommitted.")

    except Exception as exc:
        conn.rollback()
        print(f"\nERROR: {exc}", file=sys.stderr)
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()
