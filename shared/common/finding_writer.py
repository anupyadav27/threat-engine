"""
Shared Finding Writer — Task 0.5.3 [Seq 46 | BD]

Generic batch finding writer that all 5 new engines use to write evaluation
results to their respective {engine}_findings tables. Provides:

  - Batch INSERT using executemany() to avoid N+1 queries
  - Required-field validation before insert
  - Automatic UUID generation for finding_id
  - Transaction safety (rollback on error)
  - Both async (asyncpg) and sync (psycopg2) interfaces

Usage:
    from shared.common.finding_writer import FindingWriter, Finding

    writer = FindingWriter()

    findings = [
        Finding(
            scan_id="abc-123",
            tenant_id="tenant-1",
            scan_run_id="orch-456",
            resource_id="i-0abcdef1234567890",
            resource_type="ec2_instance",
            rule_id="aws.ec2.public_ip_check",
            result="FAIL",
            severity="high",
            title="EC2 instance has public IP",
            evidence={"field": "public_ip", "actual": "3.14.15.92"},
        ),
        ...
    ]

    count = await writer.write_findings(db_pool, "container", findings)
    # count → number of rows inserted

Consumed by: Tasks 1.4, 2.4, 3.5, 4.4, 5.5 (all engine evaluators)
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Fields that must be present for every finding
REQUIRED_FIELDS = {"scan_id", "tenant_id", "scan_run_id", "rule_id", "result"}


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """
    Single evaluation result for one rule against one resource.

    Maps to the standard {engine}_findings table schema.
    """

    # Required
    scan_id: str = ""
    tenant_id: str = ""
    scan_run_id: str = ""
    rule_id: str = ""
    result: str = "SKIP"  # PASS | FAIL | SKIP | ERROR

    # Resource identity
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None
    resource_arn: Optional[str] = None

    # Rule metadata
    severity: str = "info"
    title: str = ""
    description: str = ""
    remediation: str = ""

    # Evidence (JSONB)
    evidence: Dict[str, Any] = field(default_factory=dict)

    # Context
    account_id: Optional[str] = None
    region: Optional[str] = None
    csp: str = "aws"
    is_active: bool = True

    # Auto-generated
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def validate(self) -> List[str]:
        """
        Check required fields are populated.

        Returns:
            List of missing field names (empty if valid).
        """
        missing = []
        for f in REQUIRED_FIELDS:
            val = getattr(self, f, None)
            if not val:
                missing.append(f)
        return missing

    def to_tuple(self) -> tuple:
        """
        Return values tuple in INSERT column order.

        Column order matches the INSERT statement in FindingWriter.
        """
        import json

        return (
            self.finding_id,
            self.scan_id,
            self.tenant_id,
            self.scan_run_id,
            self.resource_id,
            self.resource_type,
            self.resource_arn,
            self.rule_id,
            self.result,
            self.severity,
            self.title,
            self.description,
            json.dumps(self.evidence) if isinstance(self.evidence, dict) else self.evidence,
            self.remediation,
            self.account_id,
            self.region,
            self.csp,
            self.is_active,
        )


# ---------------------------------------------------------------------------
# Finding Writer
# ---------------------------------------------------------------------------

class FindingWriter:
    """
    Batch writer for {engine}_findings tables.

    Validates findings, generates UUIDs, and inserts in batches using
    executemany for performance.

    Parameters:
        batch_size: Max findings per INSERT batch (default 500).
    """

    def __init__(self, batch_size: int = 500) -> None:
        self._batch_size = batch_size

    # ------------------------------------------------------------------
    # Async (asyncpg)
    # ------------------------------------------------------------------

    async def write_findings(
        self,
        db_pool,
        engine_name: str,
        findings: List[Finding],
    ) -> int:
        """
        Batch insert findings into {engine}_findings using asyncpg.

        Args:
            db_pool:     asyncpg connection pool.
            engine_name: Engine name (container, network, supplychain, api, risk).
            findings:    List of Finding objects.

        Returns:
            Number of rows inserted.

        Raises:
            ValueError: If any finding has missing required fields.
            Exception:  Re-raises DB errors after rollback.
        """
        if not findings:
            return 0

        # Validate all findings first
        self._validate_all(findings)

        table_name = f"{engine_name}_findings"
        scan_id_col = f"{engine_name}_scan_id"

        insert_sql = f"""
            INSERT INTO {table_name} (
                finding_id, {scan_id_col}, tenant_id, scan_run_id,
                resource_id, resource_type, resource_arn,
                rule_id, result, severity, title, description,
                evidence, remediation,
                account_id, region, csp, is_active,
                created_at
            ) VALUES (
                $1::uuid, $2::uuid, $3::uuid, $4::uuid,
                $5, $6, $7,
                $8, $9, $10, $11, $12,
                $13::jsonb, $14,
                $15, $16, $17, $18,
                NOW()
            )
        """

        total_inserted = 0

        async with db_pool.acquire() as conn:
            # Process in batches
            for i in range(0, len(findings), self._batch_size):
                batch = findings[i : i + self._batch_size]

                async with conn.transaction():
                    try:
                        await conn.executemany(
                            insert_sql,
                            [f.to_tuple() for f in batch],
                        )
                        total_inserted += len(batch)

                    except Exception as exc:
                        logger.error(
                            "Failed to insert batch %d-%d into %s: %s",
                            i, i + len(batch), table_name, exc,
                        )
                        raise

        logger.info(
            "Inserted %d findings into %s", total_inserted, table_name
        )
        return total_inserted

    # ------------------------------------------------------------------
    # Sync (psycopg2)
    # ------------------------------------------------------------------

    def write_findings_sync(
        self,
        db_conn,
        engine_name: str,
        findings: List[Finding],
    ) -> int:
        """
        Batch insert findings into {engine}_findings using psycopg2.

        Args:
            db_conn:     psycopg2 connection.
            engine_name: Engine name.
            findings:    List of Finding objects.

        Returns:
            Number of rows inserted.
        """
        if not findings:
            return 0

        self._validate_all(findings)

        table_name = f"{engine_name}_findings"
        scan_id_col = f"{engine_name}_scan_id"

        insert_sql = f"""
            INSERT INTO {table_name} (
                finding_id, {scan_id_col}, tenant_id, scan_run_id,
                resource_id, resource_type, resource_arn,
                rule_id, result, severity, title, description,
                evidence, remediation,
                account_id, region, csp, is_active,
                created_at
            ) VALUES (
                %s::uuid, %s::uuid, %s::uuid, %s::uuid,
                %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s::jsonb, %s,
                %s, %s, %s, %s,
                NOW()
            )
        """

        total_inserted = 0
        cursor = db_conn.cursor()

        try:
            for i in range(0, len(findings), self._batch_size):
                batch = findings[i : i + self._batch_size]

                try:
                    cursor.executemany(
                        insert_sql,
                        [f.to_tuple() for f in batch],
                    )
                    db_conn.commit()
                    total_inserted += len(batch)

                except Exception as exc:
                    db_conn.rollback()
                    logger.error(
                        "Failed to insert batch %d-%d into %s: %s",
                        i, i + len(batch), table_name, exc,
                    )
                    raise

        finally:
            cursor.close()

        logger.info(
            "Inserted %d findings into %s", total_inserted, table_name
        )
        return total_inserted

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate_all(self, findings: List[Finding]) -> None:
        """
        Validate all findings before insert.

        Raises ValueError listing all invalid findings (by index + missing fields).
        """
        errors: List[str] = []

        for i, finding in enumerate(findings):
            missing = finding.validate()
            if missing:
                errors.append(f"finding[{i}] missing: {', '.join(missing)}")

        if errors:
            raise ValueError(
                f"Validation failed for {len(errors)} findings:\n"
                + "\n".join(errors[:10])  # Show first 10
                + (f"\n... and {len(errors) - 10} more" if len(errors) > 10 else "")
            )


# ---------------------------------------------------------------------------
# Convenience: build Finding from RuleResult + context
# ---------------------------------------------------------------------------

def result_to_finding(
    rule_result_dict: Dict[str, Any],
    rule: Dict[str, Any],
    asset: Dict[str, Any],
    scan_id: str,
    tenant_id: str,
    scan_run_id: str,
    account_id: Optional[str] = None,
    region: Optional[str] = None,
    csp: str = "aws",
) -> Finding:
    """
    Build a Finding from a RuleResult.to_dict() + rule + asset context.

    This is the glue between RuleEvaluator output and FindingWriter input.

    Args:
        rule_result_dict: Output of RuleResult.to_dict() (result, evidence, severity).
        rule:             Rule dict (must have rule_id, title, remediation, etc.).
        asset:            Asset dict from {engine}_input_transformed (must have
                          resource_id, resource_type, resource_arn).
        scan_id:          The engine's scan ID.
        tenant_id:        Tenant identifier.
        scan_run_id: Orchestration identifier.
        account_id:       Cloud account ID (optional).
        region:           Region (optional).
        csp:              CSP name (default 'aws').

    Returns:
        Finding ready for FindingWriter.
    """
    return Finding(
        scan_id=scan_id,
        tenant_id=tenant_id,
        scan_run_id=scan_run_id,
        resource_id=asset.get("resource_id"),
        resource_type=asset.get("resource_type"),
        resource_arn=asset.get("resource_arn"),
        rule_id=rule.get("rule_id", ""),
        result=rule_result_dict.get("result", "ERROR"),
        severity=rule_result_dict.get("severity", rule.get("severity", "info")),
        title=rule.get("title", ""),
        description=rule.get("description", ""),
        evidence=rule_result_dict.get("evidence", {}),
        remediation=rule.get("remediation", ""),
        account_id=account_id,
        region=region,
        csp=csp,
    )
