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
                policies_to_db_rows,
            )
            from iam_engine.parsers.trust_analyzer import TrustAnalyzer
            from iam_engine.detectors.policy_detector import run_all_detectors

            # Load IAM resources from discovery or inventory
            data_source = os.getenv("IAM_DATA_SOURCE", "discovery").lower()
            if data_source == "inventory":
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

            # Save policy statements to DB
            all_parsed = managed_policies + inline_policies + trust_policies
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
            result["policy_findings"] = policy_findings

        except Exception as e:
            logger.error(f"AWS IAM provider analysis failed (non-fatal): {e}", exc_info=True)

        return result
