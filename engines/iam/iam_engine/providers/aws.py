"""
AWS IAM Provider

Handles AWS-specific IAM analysis:
  - Loads IAM resources from discovery_findings (or inventory_findings)
  - Parses managed, inline, and trust policies
  - Analyzes trust relationships for risky patterns
  - Saves policy statements to iam_policy_statements table
  - Runs policy-based detectors (admin access, wildcards, cross-account trusts)

This is the exact logic that was in run_scan.py lines 145-212, extracted
into a provider class for CSP-agnostic orchestration.
"""

import logging
import os
from typing import Any, Dict, List

from .base import BaseIAMProvider, empty_result

logger = logging.getLogger(__name__)


class AWSIAMProvider(BaseIAMProvider):
    """AWS IAM policy analysis provider."""

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
    ) -> Dict[str, Any]:
        """Run AWS IAM policy parsing, trust analysis, and detection.

        Args:
            scan_run_id: Pipeline scan run ID — also used as the discovery scan ID for AWS
            tenant_id: Tenant identifier
            account_id: AWS account ID

        Returns:
            Standardized result dict with policy findings and IAM entities.
        """
        result = empty_result()

        try:
            from iam_engine.parsers.policy_parser import (
                extract_managed_policies,
                extract_inline_policies,
                extract_trust_policies,
                link_managed_policies_from_attachments,
                link_managed_policies_to_roles,
                policies_to_db_rows,
            )
            from iam_engine.parsers.trust_analyzer import TrustAnalyzer
            from iam_engine.detectors.policy_detector import run_all_detectors
            from iam_engine.detectors.escalation_detector import detect_privilege_escalation_paths

            # Load IAM resources — DI > inventory > discovery
            if os.getenv("DI_ENGINE_ENABLED", "false").lower() == "true":
                from iam_engine.input.di_reader import IAMDIReader
                logger.info(f"Loading IAM data from asset_inventory (DI): scan={scan_run_id}")
                reader = IAMDIReader()
            elif os.getenv("IAM_DATA_SOURCE", "discovery").lower() == "inventory":
                from iam_engine.input.inventory_reader import IAMInventoryReader
                logger.info(f"Loading IAM data from inventory_findings: scan={scan_run_id}")
                reader = IAMInventoryReader()
            else:
                from iam_engine.input.discovery_db_reader import IAMDiscoveryReader
                logger.info(f"Loading IAM discovery data: scan={scan_run_id}")
                reader = IAMDiscoveryReader()

            resources = reader.load_iam_resources(scan_run_id, tenant_id, account_id or None)
            reader.close()

            # Extract structured IAM entities
            roles = reader.get_roles(resources)
            users = reader.get_users(resources)
            groups = reader.get_groups(resources)
            instance_profiles = reader.get_instance_profiles(resources)
            discovery_policies = reader.get_policies(resources)

            result["roles"] = roles
            result["users"] = users
            result["groups"] = groups
            result["instance_profiles"] = instance_profiles

            # Parse policies
            managed_policies = extract_managed_policies(discovery_policies, account_id)
            logger.info(f"Parsed {len(managed_policies)} managed policies")

            # Link managed policies to roles — try two paths:
            # Path A (preferred): aws.iam.list_attached_role_policies records
            #   → exact role→policy mapping, no timeout risk
            # Path B (fallback): AttachedManagedPolicies field on role records
            #   → only populated by get_account_authorization_details_roles
            managed_policy_map = {p.policy_arn: p for p in managed_policies if p.policy_arn}
            attachments = reader.get_role_managed_policy_attachments(resources)
            if attachments:
                role_managed_policies = link_managed_policies_from_attachments(
                    attachments, managed_policy_map
                )
                logger.info(
                    f"Linked {len(role_managed_policies)} per-role managed policy assignments "
                    f"via list_attached_role_policies ({len(attachments)} attachment records)"
                )
            else:
                role_managed_policies = link_managed_policies_to_roles(roles, managed_policy_map)
                logger.info(
                    f"Linked {len(role_managed_policies)} per-role managed policy assignments "
                    f"via AttachedManagedPolicies field ({len(managed_policy_map)} policies, "
                    f"{len(roles)} roles)"
                )

            inline_policies: List = []
            for role in roles:
                inline_policies.extend(extract_inline_policies(role, "role"))
            for user in users:
                inline_policies.extend(extract_inline_policies(user, "user"))
            logger.info(f"Parsed {len(inline_policies)} inline policies")

            trust_policies = extract_trust_policies(roles)
            logger.info(f"Parsed {len(trust_policies)} trust policies")

            result["managed_policies"] = managed_policies
            result["inline_policies"] = inline_policies

            # Analyze trust relationships
            trust_analyzer = TrustAnalyzer()
            trust_relationships = trust_analyzer.analyze_trust_policies(roles, account_id)
            risky_trusts = trust_analyzer.find_risky_trusts(trust_relationships)
            logger.info(f"Found {len(risky_trusts)} risky trust relationships")

            result["trust_relationships"] = trust_relationships

            # Save policy statements to DB (role_managed_policies first so per-role
            # managed statements are written even if they share a policy_arn with
            # the global managed_policies list)
            all_parsed = role_managed_policies + inline_policies + trust_policies
            db_rows = policies_to_db_rows(all_parsed, scan_run_id, tenant_id, account_id)
            result["policy_statements_rows"] = db_rows

            try:
                from iam_engine.storage.iam_db_writer import save_policy_statements
                stmt_count = save_policy_statements(scan_run_id, tenant_id, db_rows)
                logger.info(f"Saved {stmt_count} policy statements to iam_policy_statements")
            except Exception as e:
                logger.error(f"Error saving policy statements: {e}", exc_info=True)

            # Run policy-based detectors
            policy_findings = run_all_detectors(
                managed_policies=managed_policies,
                inline_policies=inline_policies,
                trust_relationships=trust_relationships,
                account_id=account_id,
            )
            logger.info(f"Policy detectors generated {len(policy_findings)} findings")

            # Run privilege escalation path detector
            _cdr_conn = None
            try:
                from engine_common.db_connections import get_cdr_conn as _get_cdr_conn
                try:
                    _cdr_conn = _get_cdr_conn()
                except Exception as _cdr_err:
                    logger.debug("CDR connection unavailable for escalation enrichment: %s", _cdr_err)

                escalation_findings = detect_privilege_escalation_paths(
                    roles=roles,
                    users=users,
                    account_id=account_id,
                    tenant_id=tenant_id,
                    scan_run_id=scan_run_id,
                    cdr_conn=_cdr_conn,
                )
                logger.info(f"Escalation detector generated {len(escalation_findings)} findings")
                policy_findings = policy_findings + escalation_findings
            except Exception as _esc_err:
                logger.warning(f"Escalation detector failed (non-fatal): {_esc_err}", exc_info=True)
            finally:
                if _cdr_conn is not None:
                    try:
                        _cdr_conn.close()
                    except Exception:
                        pass

            result["policy_findings"] = policy_findings

        except Exception as e:
            logger.error(f"AWS IAM provider analysis failed (non-fatal): {e}", exc_info=True)

        return result
