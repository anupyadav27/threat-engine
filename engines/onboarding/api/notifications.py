"""
Notifications API — dynamically generated from scan events and account health.
"""
from fastapi import APIRouter, HTTPException, Query
from typing import Optional
import os
import sys
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

try:
    from engine_common.logger import setup_logger
    logger = setup_logger(__name__, engine_name="onboarding")
except ImportError:
    import logging
    logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["notifications"])


@router.get("/notifications")
async def get_notifications(
    tenant_id: str = Query(..., description="Tenant identifier"),
    limit: int = Query(20, ge=1, le=100, description="Max notifications to return"),
    unread_only: bool = Query(False, description="Return only unread notifications"),
):
    """
    Generate notifications dynamically from:
    - Recent scan_orchestration events (completed/failed scans)
    - cloud_accounts with credential validation failures
    """
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        from engine_onboarding.database.connection_config.database_config import get_connection_string

        notifications = []
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=7)

        # ── Scan orchestration events ─────────────────────────────────────────
        try:
            shared_conn = psycopg2.connect(get_connection_string("shared"))
            try:
                with shared_conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute(
                        """
                        SELECT
                            orchestration_id,
                            provider,
                            account_id,
                            overall_status,
                            started_at,
                            completed_at,
                            trigger_type
                        FROM scan_orchestration
                        WHERE tenant_id = %s
                          AND started_at >= %s
                        ORDER BY started_at DESC
                        LIMIT 30
                        """,
                        (tenant_id, cutoff),
                    )
                    scans = cur.fetchall()
            finally:
                shared_conn.close()

            for s in scans:
                status = s.get("overall_status", "unknown")
                provider = s.get("provider") or "Cloud"
                account = s.get("account_id") or "unknown"
                ts = s.get("completed_at") or s.get("started_at")
                ts_iso = ts.isoformat() if ts and hasattr(ts, "isoformat") else str(ts or now.isoformat())
                orch_id = str(s.get("orchestration_id", ""))

                if status in ("completed", "success"):
                    notifications.append({
                        "id": f"scan-ok-{orch_id}",
                        "title": "Scan Completed",
                        "message": f"{provider.upper()} scan for account {account} completed successfully.",
                        "severity": "info",
                        "source": "scan_orchestration",
                        "timestamp": ts_iso,
                        "read": False,
                    })
                elif status in ("failed", "error"):
                    notifications.append({
                        "id": f"scan-fail-{orch_id}",
                        "title": "Scan Failed",
                        "message": f"{provider.upper()} scan for account {account} encountered an error.",
                        "severity": "high",
                        "source": "scan_orchestration",
                        "timestamp": ts_iso,
                        "read": False,
                    })
                elif status == "running":
                    notifications.append({
                        "id": f"scan-run-{orch_id}",
                        "title": "Scan In Progress",
                        "message": f"{provider.upper()} scan for account {account} is currently running.",
                        "severity": "info",
                        "source": "scan_orchestration",
                        "timestamp": ts_iso,
                        "read": False,
                    })
        except Exception as exc:
            logger.warning("notifications: scan_orchestration query failed: %s", exc)

        # ── Credential validation failures ────────────────────────────────────
        try:
            onboarding_conn = psycopg2.connect(get_connection_string("onboarding"))
            try:
                with onboarding_conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute(
                        """
                        SELECT
                            account_id,
                            provider,
                            account_name,
                            credential_validation_status,
                            updated_at
                        FROM cloud_accounts
                        WHERE tenant_id = %s
                          AND credential_validation_status IN ('invalid', 'failed', 'expired')
                        ORDER BY updated_at DESC
                        LIMIT 10
                        """,
                        (tenant_id,),
                    )
                    bad_accounts = cur.fetchall()
            finally:
                onboarding_conn.close()

            for acct in bad_accounts:
                acct_id = str(acct.get("account_id", ""))
                provider = acct.get("provider") or "Cloud"
                name = acct.get("account_name") or acct_id
                cred_status = acct.get("credential_validation_status", "invalid")
                ts = acct.get("updated_at")
                ts_iso = ts.isoformat() if ts and hasattr(ts, "isoformat") else now.isoformat()
                notifications.append({
                    "id": f"cred-{acct_id}",
                    "title": "Credential Issue Detected",
                    "message": f"{provider.upper()} account '{name}' has {cred_status} credentials. Scanning may be impacted.",
                    "severity": "critical" if cred_status == "expired" else "high",
                    "source": "credential_validation",
                    "timestamp": ts_iso,
                    "read": False,
                })
        except Exception as exc:
            logger.warning("notifications: cloud_accounts query failed: %s", exc)

        # ── Sort by timestamp desc, apply limit ───────────────────────────────
        notifications.sort(key=lambda n: n["timestamp"], reverse=True)
        if unread_only:
            notifications = [n for n in notifications if not n["read"]]
        notifications = notifications[:limit]

        return {
            "notifications": notifications,
            "total": len(notifications),
            "unread_count": sum(1 for n in notifications if not n["read"]),
        }

    except Exception as exc:
        logger.error("notifications failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))
