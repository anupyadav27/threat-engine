"""
Check Engine — CSP-Agnostic Orchestration

Orchestrates check evaluation across all cloud providers.

Flow per scan:
  1. For each requested service:
     a. Load rules:       rule_checks table (DB) merged over YAML (YAML = base, DB = override)
     b. Pre-load discoveries: discovery_findings table per for_each discovery_id
     c. For each rule × each discovery item:
        - Delegate resource ID extraction to self.evaluator (CSP-specific)
        - Evaluate rule conditions (pure logic, CSP-agnostic)
        - Write PASS/FAIL/ERROR to check_findings (or NDJSON in file mode)
  2. Mark check_report as 'completed'

This module has ZERO AWS / Azure / GCP / OCI specific code.
All CSP-specific behaviour is in providers/<csp>/evaluator/check_evaluator.py.
"""

import json
import logging
import os
import uuid
import yaml
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
from common.database.discovery_reader import DiscoveryReader
from common.utils.phase_logger import PhaseLogger
from common.utils.condition_evaluator import (
    extract_value,
    evaluate_condition,
    resolve_template,
)


class CheckEngine:
    """
    CSP-Agnostic Check Engine.

    Requires a CheckEvaluator instance for all provider-specific operations.
    """

    def __init__(
        self,
        evaluator: CheckEvaluator,
        db_manager: Optional[DatabaseManager] = None,
        use_ndjson: Optional[bool] = None,
    ):
        """
        Args:
            evaluator:   CSP-specific evaluator (must already be authenticated).
            db_manager:  Required in database mode; omit only in NDJSON mode.
            use_ndjson:  True=file mode, False=database mode, None=auto-detect.
        """
        self.evaluator = evaluator
        self.db = db_manager
        self.use_ndjson = self._determine_mode(use_ndjson)
        self.phase_logger: Optional[PhaseLogger] = None

        self.discovery_reader = DiscoveryReader()

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

        if not self.use_ndjson and not self.db:
            raise ValueError("DatabaseManager required in database mode")

        logger.info(
            "CheckEngine ready: mode=%s provider=%s rule_reader=%s",
            "NDJSON" if self.use_ndjson else "DATABASE",
            evaluator.provider,
            "yes" if self.rule_reader else "no",
        )

    # ── Mode detection ────────────────────────────────────────────────────────

    def _determine_mode(self, use_ndjson: Optional[bool]) -> bool:
        if use_ndjson is not None:
            return use_ndjson
        env = os.getenv("CHECK_MODE", "").lower()
        if env in ("ndjson", "file", "local"):
            return True
        if env in ("database", "db", "production"):
            return False
        if self.db:
            try:
                conn = self.db._get_connection()
                self.db._return_connection(conn)
                return False
            except Exception:
                return True
        return False

    # ── Discovery loading ─────────────────────────────────────────────────────

    def _load_discoveries(
        self,
        discovery_id: str,
        tenant_id: str,
        account_id: str,
        scan_id: str,
        service: str,
    ) -> List[Dict]:
        if self.use_ndjson:
            return self._load_from_ndjson(scan_id, discovery_id, service, account_id)
        return self.discovery_reader.read_discovery_records(
            discovery_id=discovery_id,
            tenant_id=tenant_id,
            account_id=account_id,
            scan_id=scan_id,
            service=service,
        )

    def _load_from_ndjson(
        self, scan_id: str, discovery_id: str, service: str, account_id: str
    ) -> List[Dict]:
        output_base = os.getenv("OUTPUT_DIR")
        base = (
            Path(output_base).parent
            if output_base
            else _project_root()
            / "engine_output"
            / f"engine_check_{self.evaluator.provider}"
            / "output"
        )
        discoveries_dir = base / "discoveries" / scan_id / "discovery"
        if not discoveries_dir.exists():
            return []

        items: List[Dict] = []
        for f in discoveries_dir.glob(f"{account_id}_*_{service}.ndjson"):
            try:
                with open(f, encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                            if rec.get("discovery_id") != discovery_id:
                                continue
                            ef = rec.get("emitted_fields", {})
                            if isinstance(ef, str):
                                ef = json.loads(ef)
                            items.append(
                                {
                                    "resource_arn": rec.get("resource_arn"),
                                    "resource_id": rec.get("resource_id"),
                                    "service": rec.get("service", service),
                                    "region": rec.get("region"),
                                    "discovery_id": rec.get("discovery_id"),
                                    "emitted_fields": ef,
                                    "first_seen_at": rec.get("first_seen_at"),
                                }
                            )
                        except (json.JSONDecodeError, Exception):
                            continue
            except Exception as exc:
                logger.error("Error reading %s: %s", f, exc)
        return items

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
        discovery_scan_run_id: str,
        customer_id: str,
        tenant_id: str,
        provider: str,
        account_id: str,
        hierarchy_type: str,
        services: List[str],
        check_source: str = "default",
        use_ndjson: Optional[bool] = None,
        scan_run_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Run security checks against discovered resources.

        Args:
            discovery_scan_run_id: Discovery scan to evaluate against.
            customer_id:       Customer identifier.
            tenant_id:         Tenant identifier.
            provider:          CSP name (aws / azure / gcp / oci).
            account_id:      Account / subscription / project ID.
            hierarchy_type:    account / subscription / project.
            services:          List of services to check, e.g. ['ec2', 's3'].
            check_source:      'default' or 'custom' — selects YAML subdirectory.
            scan_run_id:     Optional UUID; generated if omitted.

        Returns:
            Summary dict: scan_run_id, totals, mode.
        """
        use_ndjson_mode = use_ndjson if use_ndjson is not None else self.use_ndjson
        scan_run_id = scan_run_id or str(uuid.uuid4())
        mode = "NDJSON" if use_ndjson_mode else "DATABASE"

        # Phase logger
        output_base = os.getenv("OUTPUT_DIR")
        base = (
            Path(output_base).parent
            if output_base
            else _project_root()
            / "engine_output"
            / f"engine_check_{provider}"
            / "output"
        )
        output_dir = base / "checks" / scan_run_id
        self.phase_logger = PhaseLogger(scan_run_id, "checks", output_dir)
        self.phase_logger.info(
            "Check scan %s [%s] → discovery %s", scan_run_id, mode, discovery_scan_run_id
        )
        self.phase_logger.info(
            "  Provider: %s | Services: %d | Source: %s",
            provider, len(services), check_source,
        )

        # Create scan record in DB
        if not use_ndjson_mode and self.db:
            self.db.create_scan(
                scan_id=scan_run_id,
                customer_id=customer_id,
                tenant_id=tenant_id,
                provider=provider,
                account_id=account_id,
                hierarchy_type=hierarchy_type,
                scan_type="check",
                metadata={
                    "discovery_scan_run_id": discovery_scan_run_id,
                    "services": services,
                    "check_source": check_source,
                    "mode": mode,
                },
                discovery_scan_run_id=discovery_scan_run_id,
            )

        ndjson_buffer: Optional[List[Dict]] = [] if use_ndjson_mode else None
        total = passed = failed = errors = 0

        for svc_idx, service in enumerate(services, 1):
            self.phase_logger.info("[%d/%d] %s", svc_idx, len(services), service)
            try:
                checks = self._load_rules(service, provider, check_source)
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

                # Pre-load all discovery data for this service
                disc_cache: Dict[str, List[Dict]] = {}
                for ch in checks:
                    did = ch.get("for_each")
                    if did and did not in disc_cache:
                        disc_cache[did] = self._load_discoveries(
                            did, tenant_id, account_id, discovery_scan_run_id, service
                        )
                loaded = sum(1 for v in disc_cache.values() if v)
                self.phase_logger.info(
                    "  %d/%d discovery types have data", loaded, len(disc_cache)
                )

                # Evaluate each rule
                for check in checks:
                    rule_id = check.get("rule_id")
                    for_each = check.get("for_each")
                    conditions = check.get("conditions")
                    if not rule_id or not for_each or not conditions:
                        continue

                    # Resolve resource_service from metadata (cross-service fix)
                    _rmeta = _meta_map.get(rule_id, {})
                    resource_service = _rmeta.get("resource_service") or service

                    items = disc_cache.get(for_each, [])
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
                            status = "PASS" if result else "FAIL"
                            if status == "PASS":
                                passed += 1
                            else:
                                failed += 1
                            total += 1

                            # Capture actual field values for remediation context
                            actual_values = {
                                f: extract_value(item_data, f)
                                for f in checked_fields
                            }

                            region = item_record.get("region", "")

                            finding_data = {
                                "discovery_id": for_each,
                                "actual_values": actual_values,
                            }

                            if use_ndjson_mode:
                                ndjson_buffer.append(
                                    {
                                        "scan_run_id": scan_run_id,
                                        "discovery_scan_run_id": discovery_scan_run_id,
                                        "customer_id": customer_id,
                                        "tenant_id": tenant_id,
                                        "provider": provider,
                                        "account_id": account_id,
                                        "hierarchy_type": hierarchy_type,
                                        "rule_id": rule_id,
                                        "service": service,
                                        "resource_service": resource_service,
                                        "discovery_id": for_each,
                                        "region": region,
                                        "resource_arn": resource_arn,
                                        "resource_uid": resource_uid,
                                        "resource_id": resource_id,
                                        "resource_type": resource_type,
                                        "status": status,
                                        "checked_fields": checked_fields,
                                        "actual_values": actual_values,
                                        "finding_data": finding_data,
                                        "first_seen_at": datetime.now(timezone.utc).isoformat(),
                                    }
                                )
                            elif self.db:
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
                                    region=region,
                                    resource_arn=resource_arn,
                                    resource_uid=resource_uid,
                                    resource_id=resource_id,
                                    resource_type=resource_type,
                                    resource_service=resource_service,
                                    status=status,
                                    checked_fields=checked_fields,
                                    actual_values=actual_values,
                                    finding_data=finding_data,
                                )

                        except Exception as exc:
                            errors += 1
                            logger.error(
                                "Error evaluating %s: %s", rule_id, exc, exc_info=False
                            )
                            if self.db and not use_ndjson_mode:
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
        if not use_ndjson_mode and self.db:
            self.db.update_scan_status(scan_run_id, "completed")

        if use_ndjson_mode and ndjson_buffer:
            self._write_ndjson(output_dir, scan_run_id, ndjson_buffer)

        summary = {
            "scan_run_id":    scan_run_id,
            "discovery_scan_run_id": discovery_scan_run_id,
            "provider":         provider,
            "mode":             mode,
            "total_checks":     total,
            "passed":           passed,
            "failed":           failed,
            "errors":           errors,
        }
        self.phase_logger.info(
            "Scan complete: %d checks — %d PASS %d FAIL %d ERROR",
            total, passed, failed, errors,
        )
        return summary

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _load_rules(
        self, service: str, provider: str, check_source: str
    ) -> List[Dict]:
        """
        Load and merge rules: YAML (base) + rule_checks DB (override).
        DB rules win on rule_id collision (allows custom overrides without
        touching YAML files).
        """
        checks_by_id: Dict[str, Dict] = {}

        # YAML base
        yaml_path = (
            _project_root()
            / "engine_check"
            / "engine_check_aws"
            / "services"
            / service
            / "checks"
            / check_source
            / f"{service}.checks.yaml"
        )
        if yaml_path.exists():
            try:
                with open(yaml_path) as f:
                    for c in (yaml.safe_load(f) or {}).get("checks", []):
                        if c.get("rule_id"):
                            checks_by_id[c["rule_id"]] = c
                self.phase_logger.info(
                    "  YAML: %d rules for %s", len(checks_by_id), service
                )
            except Exception as exc:
                logger.warning("Failed to load YAML rules for %s: %s", service, exc)

        # DB override
        if self.rule_reader:
            try:
                for c in self.rule_reader.read_checks_for_service(service, provider):
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

    def _write_ndjson(
        self, output_dir: Path, scan_run_id: str, results: List[Dict]
    ) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        out = output_dir / "checks.ndjson"
        with open(out, "w", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps(r, default=str) + "\n")
        summary = {
            "scan_run_id": scan_run_id,
            "total":  len(results),
            "passed": sum(1 for r in results if r["status"] == "PASS"),
            "failed": sum(1 for r in results if r["status"] == "FAIL"),
            "errors": sum(1 for r in results if r["status"] == "ERROR"),
        }
        with open(output_dir / "summary.json", "w") as f:
            json.dump(summary, f, indent=2)
        logger.info("NDJSON written: %s (%d results)", out, len(results))
