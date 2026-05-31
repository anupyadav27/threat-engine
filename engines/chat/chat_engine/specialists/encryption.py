"""Encryption specialist — KMS, certificates, TLS, secrets."""

from __future__ import annotations

from typing import Dict

import psycopg2.extras

from .base import SpecialistAgent


class EncryptionSpecialist(SpecialistAgent):
    DOMAIN = "encryption"
    SYSTEM_PROMPT = """You are an encryption security specialist for a CSPM platform.
You analyze encryption posture including KMS key management, TLS/SSL certificate validity, at-rest and in-transit encryption coverage, and secrets rotation.

When answering:
- Lead with count of unencrypted resources (at-rest and in-transit separately)
- Highlight expiring/expired certificates (days remaining < 30 is critical)
- Call out resources without KMS-managed keys (using provider-managed vs customer-managed)
- Mention resources missing TLS (legacy HTTP endpoints)
- Be concise — focus on data exposure risk from encryption gaps"""

    EXTRA_TOOLS = [
        {
            "toolSpec": {
                "name": "get_encryption_summary",
                "description": "Get encryption posture statistics — unencrypted resources, certificate status, KMS coverage.",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "account_id": {"type": "string"},
                        },
                        "required": [],
                    }
                },
            }
        }
    ]

    def _execute_extra_tool(self, name: str, params: Dict) -> Dict:
        if name == "get_encryption_summary":
            return self._get_encryption_summary(params)
        return {"error": f"Unknown tool: {name}"}

    def _get_encryption_summary(self, params: Dict) -> Dict:
        conds = ["tenant_id = %s"]
        args: list = [self.tenant_id]
        if self.account_ids is not None:
            conds.append("account_id = ANY(%s)")
            args.append(self.account_ids)
        if params.get("account_id"):
            conds.append("account_id = %s")
            args.append(params["account_id"])
        where = " AND ".join(conds)

        with self.di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT
                    COUNT(*) AS total_resources,
                    COUNT(*) FILTER (WHERE is_encrypted_at_rest = FALSE) AS unencrypted_at_rest,
                    COUNT(*) FILTER (WHERE is_encrypted_in_transit = FALSE) AS unencrypted_in_transit,
                    COUNT(*) FILTER (WHERE has_kms_managed_key = TRUE) AS kms_managed_count,
                    COUNT(*) FILTER (WHERE has_valid_certificate = FALSE) AS invalid_certificates,
                    COUNT(*) FILTER (WHERE cert_days_remaining IS NOT NULL AND cert_days_remaining < 30) AS expiring_certs_30d,
                    COUNT(*) FILTER (WHERE cert_days_remaining IS NOT NULL AND cert_days_remaining < 7) AS expiring_certs_7d,
                    COUNT(*) FILTER (WHERE tls_version IN ('TLS 1.0', 'TLS 1.1', 'SSL 3.0')) AS legacy_tls,
                    MIN(cert_days_remaining) AS min_cert_days_remaining
                FROM resource_security_posture
                WHERE {where}
                """,
                args,
            )
            posture_stats = dict(cur.fetchone() or {})

            # Encryption findings
            conds_sf = ["tenant_id = %s", "source_engine = 'encryption'"]
            args_sf: list = [self.tenant_id]
            if self.account_ids is not None:
                conds_sf.append("account_id = ANY(%s)")
                args_sf.append(self.account_ids)
            where_sf = " AND ".join(conds_sf)

            cur.execute(
                f"""
                SELECT severity, COUNT(*) AS cnt
                FROM security_findings
                WHERE {where_sf}
                GROUP BY severity
                ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END
                """,
                args_sf,
            )
            finding_counts = [dict(r) for r in cur.fetchall()]

            # Certs expiring soon
            cur.execute(
                f"""
                SELECT resource_uid, resource_type, resource_name, account_id,
                       cert_days_remaining, tls_version, has_valid_certificate
                FROM resource_security_posture
                WHERE {where} AND cert_days_remaining IS NOT NULL AND cert_days_remaining < 30
                ORDER BY cert_days_remaining ASC
                LIMIT 10
                """,
                args,
            )
            expiring_certs = [dict(r) for r in cur.fetchall()]

        return {
            "encryption_posture": posture_stats,
            "finding_severity_counts": finding_counts,
            "expiring_certificates": expiring_certs,
        }
