"""
IAM Graph Writer — Creates IAM-specific edges in the Neo4j security graph.

Edge types created:
  - HAS_POLICY: IAMRole/IAMUser → IAMPolicy (managed policy attachments)
  - ASSUMES: IAMRole → IAMRole (cross-account / same-account trust)
  - MEMBER_OF: IAMUser → IAMGroup
  - CAN_ACCESS: IAMRole → Resource (from policy statements with specific ARNs)

Follows batched UNWIND pattern from graph_builder.py (batch_size=500).
"""

import logging
import os
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

BATCH_SIZE = 500


class IAMGraphWriter:
    """Creates IAM-specific edges in Neo4j security graph."""

    def __init__(
        self,
        neo4j_uri: Optional[str] = None,
        neo4j_user: Optional[str] = None,
        neo4j_password: Optional[str] = None,
    ):
        self._uri = neo4j_uri or os.getenv("NEO4J_URI", "neo4j+s://17ec5cbb.databases.neo4j.io")
        self._user = neo4j_user or os.getenv("NEO4J_USER", "neo4j")
        self._password = neo4j_password or os.getenv("NEO4J_PASSWORD", "")
        self._driver = None

    def _get_driver(self):
        if self._driver is None:
            from neo4j import GraphDatabase
            self._driver = GraphDatabase.driver(
                self._uri, auth=(self._user, self._password)
            )
        return self._driver

    def close(self):
        if self._driver:
            self._driver.close()
            self._driver = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def create_iam_edges(
        self,
        tenant_id: str,
        roles: List[Dict],
        users: List[Dict],
        groups: List[Dict],
        managed_policies: List[Any],
        trust_relationships: List[Any],
        instance_profiles: List[Dict],
    ) -> Dict[str, int]:
        """
        Create all IAM graph edges. Returns counts by edge type.

        Args:
            tenant_id: Tenant identifier
            roles: Role dicts from discovery (with AttachedManagedPolicies)
            users: User dicts from discovery (with AttachedManagedPolicies, GroupList)
            groups: Group dicts from discovery
            managed_policies: ParsedPolicy objects
            trust_relationships: TrustRelationship objects
            instance_profiles: Instance profile dicts (with Roles)

        Returns:
            Dict of edge_type -> count created
        """
        driver = self._get_driver()
        counts = {}

        with driver.session() as session:
            counts["HAS_POLICY"] = self._create_has_policy_edges(session, roles, users, tenant_id)
            counts["ASSUMES"] = self._create_assumes_edges(session, trust_relationships, tenant_id)
            counts["MEMBER_OF"] = self._create_member_of_edges(session, users, tenant_id)
            counts["CAN_ACCESS"] = self._create_can_access_edges(session, managed_policies, tenant_id)

        logger.info(f"IAM graph edges created: {counts}")
        return counts

    def _create_has_policy_edges(
        self, session, roles: List[Dict], users: List[Dict], tenant_id: str
    ) -> int:
        """Create HAS_POLICY edges from role/user to managed policy."""
        batch = []

        for role in roles:
            role_arn = role.get("Arn", "")
            if not role_arn:
                continue
            for pol in (role.get("AttachedManagedPolicies") or []):
                if not isinstance(pol, dict):
                    continue
                pol_arn = pol.get("PolicyArn", "")
                if pol_arn:
                    batch.append({
                        "src": role_arn,
                        "dst": pol_arn,
                        "policy_type": "managed",
                    })

        for user in users:
            user_arn = user.get("Arn", "")
            if not user_arn:
                continue
            for pol in (user.get("AttachedManagedPolicies") or []):
                if not isinstance(pol, dict):
                    continue
                pol_arn = pol.get("PolicyArn", "")
                if pol_arn:
                    batch.append({
                        "src": user_arn,
                        "dst": pol_arn,
                        "policy_type": "managed",
                    })

        return self._run_batched_merge(session, batch, "HAS_POLICY", [
            "r.policy_type = p.policy_type",
            "r.attack_path_category = ''",
        ])

    def _create_assumes_edges(
        self, session, trust_relationships: List[Any], tenant_id: str
    ) -> int:
        """Create ASSUMES edges for role-to-role trust relationships."""
        batch = []
        for trust in trust_relationships:
            if trust.effect != "Allow":
                continue
            if trust.principal_type not in ("role", "account"):
                continue

            # For account-level trust (arn:aws:iam::ACCT:root), link to the root
            principal = trust.trusted_principal
            if not principal or principal == "*":
                continue

            attack_category = ""
            if trust.is_cross_account:
                attack_category = "lateral_movement"
            elif trust.principal_type == "role":
                attack_category = "privilege_escalation"

            batch.append({
                "src": principal,
                "dst": trust.source_role_arn,
                "attack_path_category": attack_category,
                "is_cross_account": trust.is_cross_account,
                "has_external_id": trust.has_external_id,
            })

        return self._run_batched_merge(session, batch, "ASSUMES", [
            "r.attack_path_category = p.attack_path_category",
            "r.is_cross_account = p.is_cross_account",
            "r.has_external_id = p.has_external_id",
        ])

    def _create_member_of_edges(
        self, session, users: List[Dict], tenant_id: str
    ) -> int:
        """Create MEMBER_OF edges from users to groups."""
        batch = []
        for user in users:
            user_arn = user.get("Arn", "")
            if not user_arn:
                continue
            for group_name in (user.get("GroupList") or []):
                if not isinstance(group_name, str):
                    continue
                # Construct group ARN from user ARN
                # arn:aws:iam::ACCT:user/NAME -> arn:aws:iam::ACCT:group/NAME
                parts = user_arn.split(":")
                if len(parts) >= 6:
                    acct = parts[4]
                    group_arn = f"arn:aws:iam::{acct}:group/{group_name}"
                    batch.append({"src": user_arn, "dst": group_arn})

        return self._run_batched_merge(session, batch, "MEMBER_OF", [
            "r.attack_path_category = ''",
        ])

    def _create_can_access_edges(
        self, session, managed_policies: List[Any], tenant_id: str
    ) -> int:
        """
        Create CAN_ACCESS edges from identity → resource based on policy statements.

        Only creates edges for statements with specific resource ARNs (not wildcards).
        """
        batch = []
        for policy in managed_policies:
            if policy.is_aws_managed:
                continue
            if not policy.attached_to_arn:
                continue
            for stmt in policy.statements:
                if stmt.effect != "Allow":
                    continue
                for resource_arn in stmt.resources:
                    if resource_arn == "*":
                        continue  # Skip wildcards
                    if not resource_arn.startswith("arn:"):
                        continue
                    # Determine attack category based on actions
                    attack_cat = self._classify_access_category(stmt.actions)
                    batch.append({
                        "src": policy.attached_to_arn,
                        "dst": resource_arn,
                        "attack_path_category": attack_cat,
                        "actions": ",".join(stmt.actions[:10]),  # Truncate for property
                    })

        return self._run_batched_merge(session, batch, "CAN_ACCESS", [
            "r.attack_path_category = p.attack_path_category",
            "r.actions = p.actions",
        ])

    @staticmethod
    def _classify_access_category(actions: List[str]) -> str:
        """Classify the attack_path_category based on action patterns."""
        actions_lower = [a.lower() for a in actions]
        if "*" in actions_lower:
            return "privilege_escalation"
        data_prefixes = ("s3:", "rds:", "dynamodb:", "secretsmanager:", "kms:")
        if any(a.startswith(p) for a in actions_lower for p in data_prefixes):
            return "data_access"
        exec_prefixes = ("lambda:", "ecs:", "ec2:run", "ssm:send")
        if any(a.startswith(p) for a in actions_lower for p in exec_prefixes):
            return "execution"
        iam_prefixes = ("iam:", "sts:")
        if any(a.startswith(p) for a in actions_lower for p in iam_prefixes):
            return "privilege_escalation"
        return ""

    def _run_batched_merge(
        self,
        session,
        batch: List[Dict],
        rel_type: str,
        set_clauses: List[str],
    ) -> int:
        """Run batched MERGE for a relationship type. Returns count created."""
        if not batch:
            return 0

        sets = ", ".join(set_clauses)
        cypher = f"""
            UNWIND $batch AS p
            MATCH (a:Resource {{uid: p.src}})
            MATCH (b:Resource {{uid: p.dst}})
            MERGE (a)-[r:`{rel_type}`]->(b)
            SET {sets}
            RETURN COUNT(*) AS c
        """

        count = 0
        for i in range(0, len(batch), BATCH_SIZE):
            chunk = batch[i:i + BATCH_SIZE]
            try:
                result = session.run(cypher, batch=chunk)
                record = result.single()
                count += record["c"] if record else 0
            except Exception as exc:
                logger.debug(f"IAM graph batch failed ({rel_type}): {exc}")

        return count
