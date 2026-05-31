"""
Check Engine — CSP-Agnostic Orchestration

Orchestrates check evaluation across all cloud providers.

Flow per scan:
  1. For each requested service:
     a. Load rules:       rule_checks table (DB) merged over YAML (YAML = base, DB = override)
     b. Pre-load resources: inventory_findings table per for_each discovery_id
     c. For each rule × each resource item:
        - Delegate resource ID extraction to self.evaluator (CSP-specific)
        - Evaluate rule conditions (pure logic, CSP-agnostic)
        - Write PASS/FAIL/ERROR to check_findings
  2. Mark check_report as 'completed'

Data source: inventory_findings (always — merges all emitted fields from discovery per resource).

This module has ZERO AWS / Azure / GCP / OCI specific code.
All CSP-specific behaviour is in providers/<csp>/evaluator/check_evaluator.py.
"""

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _project_root() -> Path:
    """Repo root — works both in container (/app) and local checkout."""
    if Path("/app").exists():
        return Path("/app")
    return Path(__file__).resolve().parent.parent.parent.parent


from common.models.evaluator_interface import CheckEvaluator
from common.database.database_manager import DatabaseManager
from common.database.rule_reader import RuleReader
from common.database.inventory_reader import InventoryReader

from common.utils.phase_logger import PhaseLogger
from common.utils.condition_evaluator import (
    extract_value,
    field_exists,
    evaluate_condition,
    resolve_template,
)


class CheckEngine:
    """
    CSP-Agnostic Check Engine.

    Reads enriched resources from inventory_findings (which merges all
    emitted fields from all discovery ops into one record per resource).
    Requires a CheckEvaluator instance for all provider-specific operations.
    """

    def __init__(
        self,
        evaluator: CheckEvaluator,
        db_manager: Optional[DatabaseManager] = None,
    ):
        """
        Args:
            evaluator:   CSP-specific evaluator (must already be authenticated).
            db_manager:  DatabaseManager for writing check_findings results.
        """
        self.evaluator = evaluator
        self.db = db_manager
        self.phase_logger: Optional[PhaseLogger] = None

        if os.getenv("DI_ENGINE_ENABLED", "false").lower() == "true":
            from common.database.di_reader import DIReader
            self.inventory_reader = DIReader()
            logger.info("Check engine reading from asset_inventory (DI)")
        else:
            self.inventory_reader = InventoryReader()
            logger.info("Check engine reading from inventory_findings")

        self.rule_reader: Optional[RuleReader] = None
        try:
            rr = RuleReader()
            if rr.check_connection(evaluator.provider):
                self.rule_reader = rr
                logger.info("RuleReader initialised — loading rules from rule_checks table")
            else:
                logger.warning("RuleReader connection failed — YAML rules only")
        except Exception as exc:
            logger.warning("RuleReader init failed: %s", exc)

        if not self.db:
            raise ValueError("DatabaseManager required")

        logger.info(
            "CheckEngine ready: provider=%s rule_reader=%s",
            evaluator.provider,
            "yes" if self.rule_reader else "no",
        )

    # ── Resource loading ──────────────────────────────────────────────────────

    def _load_resources(
        self,
        discovery_id: str,
        tenant_id: str,
        account_id: str,
        scan_id: str,
        service: str,
    ) -> List[Dict]:
        """Load enriched resources from inventory_findings for a given discovery_id."""
        return self.inventory_reader.read_discovery_records(
            discovery_id=discovery_id,
            tenant_id=tenant_id,
            account_id=account_id,
            scan_id=scan_id,
            service=service,
        )

    # ── Condition evaluation (CSP-agnostic) ───────────────────────────────────

    def _evaluate_conditions(self, conditions: Dict, context: Dict) -> bool:
        if "all" in conditions:
            return all(
                self._evaluate_conditions(c, context) for c in conditions["all"]
            )
        if "any" in conditions:
            return any(
                self._evaluate_conditions(c, context) for c in conditions["any"]
            )
        var = conditions.get("var")
        op = conditions.get("op")
        value = conditions.get("value")
        if isinstance(value, str) and "{{" in value:
            value = resolve_template(value, context)
        actual = extract_value(context, var) if var else None
        return evaluate_condition(actual, op, value)

    def _extract_checked_fields(self, conditions: Dict) -> List[str]:
        fields: List[str] = []
        for sub in conditions.get("all", []) + conditions.get("any", []):
            fields.extend(self._extract_checked_fields(sub))
        var = conditions.get("var", "")
        if var.startswith("item."):
            fields.append(var[5:])
        return list(set(fields))

    # ── Main entry point ──────────────────────────────────────────────────────

    def run_check_scan(
        self,
        discovery_scan_id: str,
        customer_id: str,
        tenant_id: str,
        provider: str,
        account_id: str,
        hierarchy_type: str,
        services: List[str],
        check_source: str = "default",
        scan_run_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Run security checks against enriched inventory resources.

        Args:
            discovery_scan_id: Scan run ID (shared across all engines in a pipeline run).
            customer_id:       Customer identifier.
            tenant_id:         Tenant identifier.
            provider:          CSP name (aws / azure / gcp / oci / ibm / alicloud).
            account_id:        Account / subscription / project ID.
            hierarchy_type:    account / subscription / project.
            services:          List of services to check, e.g. ['ec2', 's3'].
            check_source:      'default' or 'custom' — selects YAML subdirectory.
            scan_run_id:       Optional UUID; generated if omitted.

        Returns:
            Summary dict: scan_run_id, totals.
        """
        scan_run_id = scan_run_id or str(uuid.uuid4())

        # Phase logger
        output_dir = (
            _project_root()
            / "engine_output"
            / f"engine_check_{provider}"
            / "output"
            / "checks"
            / scan_run_id
        )
        self.phase_logger = PhaseLogger(scan_run_id, "checks", output_dir)
        self.phase_logger.info(
            "Check scan %s → inventory scan %s", scan_run_id, discovery_scan_id
        )
        self.phase_logger.info(
            "  Provider: %s | Services: %d | Source: %s",
            provider, len(services), check_source,
        )

        # Create scan record in DB
        self.db.create_scan(
            scan_id=scan_run_id,
            customer_id=customer_id,
            tenant_id=tenant_id,
            provider=provider,
            account_id=account_id,
            hierarchy_type=hierarchy_type,
            scan_type="check",
            metadata={
                "discovery_scan_id": discovery_scan_id,
                "services": services,
                "check_source": check_source,
            },
            discovery_scan_id=discovery_scan_id,
        )

        total = passed = failed = errors = 0

        for svc_idx, service in enumerate(services, 1):
            self.phase_logger.info("[%d/%d] %s", svc_idx, len(services), service)
            try:
                checks = self._load_rules(service, provider, check_source, tenant_id, account_id)
                if not checks:
                    self.phase_logger.warning("  No checks found for %s", service)
                    continue
                self.phase_logger.info("  %d rules (merged YAML+DB)", len(checks))

                # Pre-load rule metadata for resource_service resolution
                _meta_map: Dict[str, Dict] = {}
                if self.rule_reader:
                    try:
                        _rule_ids = [c.get("rule_id") for c in checks if c.get("rule_id")]
                        _meta_map = self.rule_reader.read_metadata_for_rules(_rule_ids)
                    except Exception:
                        pass

                # Pre-load all inventory resources for this service
                resource_cache: Dict[str, List[Dict]] = {}
                for ch in checks:
                    did = ch.get("for_each")
                    if did and did not in resource_cache:
                        resource_cache[did] = self._load_resources(
                            did, tenant_id, account_id, discovery_scan_id, service
                        )
                loaded = sum(1 for v in resource_cache.values() if v)
                self.phase_logger.info(
                    "  %d/%d resource types have data", loaded, len(resource_cache)
                )

                # Evaluate each rule
                for check in checks:
                    rule_id = check.get("rule_id")
                    for_each = check.get("for_each")
                    conditions = check.get("conditions")
                    if not rule_id or not for_each or not conditions:
                        continue

                    # Resolve resource_service and severity from metadata
                    _rmeta = _meta_map.get(rule_id, {})
                    resource_service = _rmeta.get("resource_service") or service
                    severity = _rmeta.get("severity")

                    items = resource_cache.get(for_each, [])
                    if not items:
                        continue

                    for item_record in items:
                        try:
                            item_data = self._parse_emitted_fields(item_record)

                            # CSP-specific: extract resource identifiers
                            ids = self.evaluator.extract_resource_identifiers(
                                item_record=item_record,
                                emitted_fields=item_data,
                                service=service,
                                discovery_id=for_each,
                                region=item_record.get("region", ""),
                                account_id=account_id,
                            )
                            resource_arn = ids.get("resource_arn")
                            resource_uid = ids.get("resource_uid") or resource_arn
                            resource_id = ids.get("resource_id")
                            resource_type = ids.get("resource_type") or service

                            # CSP-agnostic: evaluate conditions
                            result = self._evaluate_conditions(
                                conditions, {"item": item_data}
                            )
                            checked_fields = self._extract_checked_fields(conditions)

                            # Detect "field not captured" — ALL checked field keys are
                            # absent from discovery data (not just None-valued).
                            # Uses field_exists() to distinguish:
                            #   • key present, value=None  → field captured, evaluate normally
                            #   • key absent entirely      → field not captured by discovery
                            all_data_missing = (
                                bool(checked_fields)
                                and all(
                                    not field_exists(item_data, f)
                                    for f in checked_fields
                                )
                            )

                            if all_data_missing:
                                # Field(s) not captured by discovery API.
                                # Still resolve the result: if the condition PASSES with
                                # missing data (e.g. is_false on absent boolean = PASS),
                                # record PASS; otherwise record FAIL (security gap).
                                # NOT_APPLICABLE is no longer used — every check resolves.
                                if result:
                                    status = "PASS"
                                    passed += 1
                                else:
                                    status = "FAIL"
                                    failed += 1
                            elif result:
                                status = "PASS"
                                passed += 1
                            else:
                                status = "FAIL"
                                failed += 1
                            total += 1

                            actual_values = {
                                f: extract_value(item_data, f)
                                for f in checked_fields
                            }

                            self.db.store_check_result(
                                scan_id=scan_run_id,
                                customer_id=customer_id,
                                tenant_id=tenant_id,
                                provider=provider,
                                account_id=account_id,
                                hierarchy_type=hierarchy_type,
                                rule_id=rule_id,
                                service=service,
                                discovery_id=for_each,
                                region=item_record.get("region", ""),
                                resource_arn=resource_arn,
                                resource_uid=resource_uid,
                                resource_id=resource_id,
                                resource_type=resource_type,
                                resource_service=resource_service,
                                status=status,
                                severity=severity,
                                checked_fields=checked_fields,
                                actual_values=actual_values,
                                finding_data={
                                    "discovery_id": for_each,
                                    "actual_values": actual_values,
                                },
                            )

                        except Exception as exc:
                            errors += 1
                            logger.error(
                                "Error evaluating %s: %s", rule_id, exc, exc_info=False
                            )
                            try:
                                self.db.store_check_result(
                                    scan_id=scan_run_id,
                                    customer_id=customer_id,
                                    tenant_id=tenant_id,
                                    provider=provider,
                                    account_id=account_id,
                                    hierarchy_type=hierarchy_type,
                                    rule_id=rule_id,
                                    service=service,
                                    discovery_id=for_each,
                                    region=item_record.get("region", ""),
                                    resource_arn=item_record.get("resource_arn"),
                                    resource_uid=item_record.get("resource_arn"),
                                    resource_id=item_record.get("resource_id"),
                                    status="ERROR",
                                    finding_data={"error": str(exc), "rule_id": rule_id},
                                )
                            except Exception:
                                pass

            except Exception as exc:
                self.phase_logger.error(
                    "Service %s failed: %s", service, exc, exc_info=True
                )

        # Finalise
        self.db.update_scan_status(scan_run_id, "completed")

        summary = {
            "scan_run_id":       scan_run_id,
            "discovery_scan_id": discovery_scan_id,
            "provider":          provider,
            "total_checks":      total,
            "passed":            passed,
            "failed":            failed,
            "errors":            errors,
        }
        self.phase_logger.info(
            "Scan complete: %d checks — %d PASS %d FAIL %d ERROR",
            total, passed, failed, errors,
        )
        return summary

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _load_rules(
        self,
        service: str,
        provider: str,
        check_source: str,
        tenant_id: Optional[str] = None,
        account_id: Optional[str] = None,
    ) -> List[Dict]:
        """Load rules from rule_checks DB table, filtered by tenant suppressions when available."""
        checks_by_id: Dict[str, Dict] = {}
        if self.rule_reader:
            try:
                if tenant_id:
                    checks = self.rule_reader.read_checks_for_service_tenant(
                        service, provider, tenant_id, account_id
                    )
                else:
                    checks = self.rule_reader.read_checks_for_service(service, provider)
                for c in checks:
                    if c.get("rule_id"):
                        checks_by_id[c["rule_id"]] = c
            except Exception as exc:
                logger.warning("Failed to load DB rules for %s: %s", service, exc)
        return list(checks_by_id.values())

    @staticmethod
    def _parse_emitted_fields(item_record: Dict) -> Dict:
        """Parse emitted_fields to a dict; unwrap single-key operation wrappers."""
        ef = item_record.get("emitted_fields")
        if isinstance(ef, str):
            try:
                data = json.loads(ef)
            except (json.JSONDecodeError, TypeError):
                data = {}
        elif isinstance(ef, dict):
            data = ef
        else:
            data = {}

        # Unwrap single-key operation wrapper: {'describe_instances': {'item': {...}}}
        if data and len(data) == 1:
            k = next(iter(data))
            if any(k.startswith(p) for p in ("get_", "list_", "describe_")):
                v = data[k]
                if isinstance(v, dict):
                    data = v.get("item", v)

        return data
