"""
Attack Path Engine — Posture Updater.

Writes attack-path signals back to resource_security_posture (threat_engine_inventory DB)
after all paths have been persisted.

Signals written per resource:
  is_on_attack_path=True
  attack_path_count=<count of paths containing this resource>
  blast_radius_count=<count of distinct crown jewels reachable from this resource>
  is_choke_point=True (for top-10 choke nodes only)
  choke_point_path_count=<paths_blocked_if_fixed>
  max_epss (if higher than previously stored)
  critical_misconfig_count
  high_misconfig_count

Uses upsert_posture_signals() from shared/common/posture_writer.py.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Dict, List, Set

from ..models.attack_path import ChokePoint, Path

logger = logging.getLogger("attack-path.posture_updater")

try:
    from engine_common.posture_writer import upsert_posture_signals
    _POSTURE_WRITER_AVAILABLE = True
except ImportError:
    logger.warning("posture_writer not available — posture signals will not be written")
    _POSTURE_WRITER_AVAILABLE = False

    def upsert_posture_signals(*args: Any, **kwargs: Any) -> dict:  # type: ignore[misc]
        return {}


def update_attack_path_signals(
    inventory_conn: Any,
    paths: List[Path],
    choke_points: List[ChokePoint],
    tenant_id: str,
    scan_run_id: str,
    account_id: str = "",
    provider: str = "aws",
) -> None:
    """Write attack-path signals to resource_security_posture for all on-path resources.

    Args:
        inventory_conn:  psycopg2 connection to threat_engine_inventory DB.
        paths:           Deduplicated Path objects from deduplicator.
        choke_points:    Detected choke points from choke_point_detector.
        tenant_id:       Tenant identifier — written to every posture row.
        scan_run_id:     Current pipeline run UUID.
        account_id:      Cloud account ID.
        provider:        CSP identifier.
    """
    if not paths:
        return

    # Build choke point lookup: node_uid → ChokePoint
    choke_lookup: Dict[str, ChokePoint] = {cp.node_uid: cp for cp in choke_points}

    # Aggregate signals per resource_uid across all paths
    resource_path_count: Dict[str, int] = defaultdict(int)
    resource_crown_jewels: Dict[str, Set[str]] = defaultdict(set)
    resource_max_epss: Dict[str, float] = {}
    resource_crit_misc: Dict[str, int] = defaultdict(int)
    resource_high_misc: Dict[str, int] = defaultdict(int)

    for p in paths:
        for uid in p.node_uids:
            resource_path_count[uid] += 1
            if p.crown_jewel_uid:
                resource_crown_jewels[uid].add(p.crown_jewel_uid)
            if p.max_epss is not None:
                existing = resource_max_epss.get(uid)
                if existing is None or p.max_epss > existing:
                    resource_max_epss[uid] = p.max_epss
            resource_crit_misc[uid] += p.misconfig_count
            resource_high_misc[uid] += p.threat_count

    all_resource_uids = set(resource_path_count.keys())

    if not all_resource_uids:
        return

    logger.info(
        '{"engine":"attack-path","stage":"posture_update","tenant_id":"%s",'
        '"resources_to_update":%d}',
        tenant_id,
        len(all_resource_uids),
    )

    for uid in all_resource_uids:
        is_choke = uid in choke_lookup
        cp = choke_lookup.get(uid)

        signals: Dict[str, Any] = {
            "is_on_attack_path": True,
            "attack_path_count": resource_path_count[uid],
            "blast_radius_count": len(resource_crown_jewels[uid]),
        }

        if is_choke and cp:
            signals["is_choke_point"] = True
            signals["paths_blocked_if_fixed"] = cp.paths_blocked_if_fixed

        epss = resource_max_epss.get(uid)
        if epss is not None:
            signals["epss_max"] = epss

        try:
            upsert_posture_signals(
                inventory_conn,
                resource_uid=uid,
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                account_id=account_id,
                provider=provider,
                resource_type="",          # type unknown at path level — updated by engine-specific signals
                **signals,
            )
        except Exception as exc:
            logger.warning(
                "posture update failed for resource_uid=%s: %s",
                uid,
                exc,
            )


def update_composite_flags(
    inventory_conn: Any,
    tenant_id: str,
    scan_run_id: str,
) -> None:
    """Compute cross-engine composite flags from merged resource_security_posture.

    Runs a single bulk UPDATE per flag set — no per-row Python loop.
    Runs AFTER all Stage-5 engines have written their dimension columns.

    Flags computed:
      unencrypted_pii_store          data_classification IN pii/phi/pci AND NOT is_encrypted_at_rest
      internet_exposed_with_pii      is_internet_exposed AND data_classification IN pii/phi/pci
      admin_role_without_mfa         is_admin_role AND NOT mfa_enforced
      exploitable_exposed_resource   is_internet_exposed AND has_known_exploit
      cdr_active_on_unencrypted      has_active_cdr_actor AND NOT is_encrypted_at_rest
      active_cdr_actor_on_admin_role is_admin_role AND has_active_cdr_actor (highest risk signal)
      api_public_no_waf              api_publicly_accessible AND NOT api_has_waf
      api_public_no_auth             api_publicly_accessible AND api_auth_type='none'
      reachable_pii_store_count      total PII stores in scan, set for admin/pii-access resources
    """
    try:
        with inventory_conn.cursor() as cur:
            # ── Composite boolean flags (single UPDATE covers all eight) ──────────
            # Scoped by tenant_id only — NOT scan_run_id.
            # resource_security_posture has UNIQUE(resource_uid, tenant_id); each
            # resource has exactly one row. Different engines update it at different
            # scan times, so scan_run_id varies per row. Filtering by scan_run_id
            # would skip resources not touched in the current scan and leave their
            # composite flags stale.
            cur.execute("""
                UPDATE resource_security_posture SET
                    unencrypted_pii_store = (
                        data_classification IN ('pii', 'phi', 'pci')
                        AND is_encrypted_at_rest = FALSE
                    ),
                    internet_exposed_with_pii = (
                        is_internet_exposed = TRUE
                        AND data_classification IN ('pii', 'phi', 'pci')
                    ),
                    admin_role_without_mfa = (
                        is_admin_role = TRUE
                        AND mfa_enforced = FALSE
                    ),
                    exploitable_exposed_resource = (
                        is_internet_exposed = TRUE
                        AND has_known_exploit = TRUE
                    ),
                    cdr_active_on_unencrypted = (
                        has_active_cdr_actor = TRUE
                        AND is_encrypted_at_rest = FALSE
                    ),
                    active_cdr_actor_on_admin_role = (
                        is_admin_role = TRUE
                        AND has_active_cdr_actor = TRUE
                    ),
                    api_public_no_waf = (
                        api_publicly_accessible = TRUE
                        AND (api_has_waf IS NULL OR api_has_waf = FALSE)
                    ),
                    api_public_no_auth = (
                        api_publicly_accessible = TRUE
                        AND (api_auth_type IS NULL OR api_auth_type = 'none')
                    ),
                    updated_at = NOW()
                WHERE tenant_id = %s
            """, (tenant_id,))

            # ── reachable_pii_store_count: for admin/pii-access resources ────────
            cur.execute("""
                WITH pii_count AS (
                    SELECT COUNT(*) AS cnt
                    FROM resource_security_posture
                    WHERE tenant_id = %s
                      AND data_classification IN ('pii', 'phi', 'pci')
                )
                UPDATE resource_security_posture SET
                    reachable_pii_store_count = (SELECT cnt FROM pii_count),
                    updated_at = NOW()
                WHERE tenant_id = %s
                  AND (is_admin_role = TRUE OR can_access_pii = TRUE)
            """, (tenant_id, tenant_id))

        inventory_conn.commit()
        logger.info(
            '{"engine":"attack-path","stage":"composite_flags","tenant_id":"%s",'
            '"scan_run_id":"%s","status":"ok"}',
            tenant_id, scan_run_id,
        )
    except Exception as exc:
        logger.warning("Composite flag update failed (non-fatal): %s", exc)
