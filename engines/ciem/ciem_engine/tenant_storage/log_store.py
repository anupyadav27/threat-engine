"""
Multi-Tenant Log Store — organizes collected logs per tenant/CSP/account.

Storage layout (S3 or local filesystem):
  {base_path}/
    └── {tenant_id}/
        └── {csp}/
            └── {account_id}/
                ├── cloudtrail/
                │   └── {year}/{month}/{day}/
                │       └── {timestamp}_{region}_{source_hash}.json.gz
                ├── vpc_flow/
                │   └── {year}/{month}/{day}/
                │       └── {timestamp}_{vpc_id}.log.gz
                ├── s3_access/
                │   └── {year}/{month}/{day}/
                │       └── {timestamp}_{bucket}.log.gz
                ├── alb/
                │   └── {year}/{month}/{day}/
                │       └── {timestamp}_{lb_name}.log.gz
                └── _metadata/
                    ├── collection_state.json    ← last collected timestamp per source
                    └── source_registry.json     ← known log sources for this account

For SaaS multi-customer:
  - Each tenant gets isolated storage prefix
  - No cross-tenant data access
  - Collection state tracks incremental sync (only fetch new logs)
  - Source registry caches discovered log locations
"""

import gzip
import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class TenantLogStore:
    """Manages per-tenant log storage with incremental collection state."""

    def __init__(self, base_path: str = None):
        self.base_path = base_path or os.getenv(
            "LOG_STORE_PATH",
            os.path.join(os.getenv("OUTPUT_DIR", "/output"), "logs")
        )

    def _tenant_path(self, tenant_id: str, csp: str, account_id: str) -> Path:
        return Path(self.base_path) / tenant_id / csp / account_id

    def _log_path(self, tenant_id: str, csp: str, account_id: str,
                  source_type: str, event_time: datetime) -> Path:
        base = self._tenant_path(tenant_id, csp, account_id) / source_type
        return base / f"{event_time.year:04d}" / f"{event_time.month:02d}" / f"{event_time.day:02d}"

    # ── Write ──

    def store_events(
        self,
        events: List[Dict],
        tenant_id: str,
        csp: str,
        account_id: str,
        source_type: str,
    ) -> str:
        """Store normalized events as gzipped JSON.

        Returns path to the stored file.
        """
        if not events:
            return ""

        now = datetime.now(timezone.utc)
        log_dir = self._log_path(tenant_id, csp, account_id, source_type, now)
        log_dir.mkdir(parents=True, exist_ok=True)

        # Generate unique filename
        content_hash = hashlib.md5(json.dumps(events[:3]).encode()).hexdigest()[:8]
        filename = f"{now.strftime('%Y%m%dT%H%M%S')}_{content_hash}.json.gz"
        filepath = log_dir / filename

        # Write gzipped JSON
        with gzip.open(filepath, "wt", encoding="utf-8") as f:
            for event in events:
                f.write(json.dumps(event, default=str) + "\n")

        logger.info(f"Stored {len(events)} events → {filepath}")
        return str(filepath)

    # ── Collection State (incremental sync) ──

    def get_collection_state(self, tenant_id: str, csp: str, account_id: str) -> Dict:
        """Get last collected timestamp per source type.

        Returns: {source_type: {last_collected: ISO timestamp, last_key: S3 key}}
        """
        meta_path = self._tenant_path(tenant_id, csp, account_id) / "_metadata" / "collection_state.json"
        if meta_path.exists():
            return json.loads(meta_path.read_text())
        return {}

    def update_collection_state(
        self,
        tenant_id: str,
        csp: str,
        account_id: str,
        source_type: str,
        last_collected: datetime,
        last_key: str = "",
        events_count: int = 0,
    ):
        """Update collection state after successful collection."""
        meta_dir = self._tenant_path(tenant_id, csp, account_id) / "_metadata"
        meta_dir.mkdir(parents=True, exist_ok=True)
        state_path = meta_dir / "collection_state.json"

        state = {}
        if state_path.exists():
            state = json.loads(state_path.read_text())

        state[source_type] = {
            "last_collected": last_collected.isoformat(),
            "last_key": last_key,
            "events_count": events_count,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

        state_path.write_text(json.dumps(state, indent=2))
        logger.info(f"Updated collection state: {tenant_id}/{csp}/{account_id}/{source_type} → {last_collected.isoformat()}")

    # ── Source Registry ──

    def get_source_registry(self, tenant_id: str, csp: str, account_id: str) -> List[Dict]:
        """Get cached log source locations for this account."""
        meta_path = self._tenant_path(tenant_id, csp, account_id) / "_metadata" / "source_registry.json"
        if meta_path.exists():
            return json.loads(meta_path.read_text())
        return []

    def update_source_registry(self, tenant_id: str, csp: str, account_id: str, sources: List[Dict]):
        """Cache discovered log sources."""
        meta_dir = self._tenant_path(tenant_id, csp, account_id) / "_metadata"
        meta_dir.mkdir(parents=True, exist_ok=True)
        registry_path = meta_dir / "source_registry.json"
        registry_path.write_text(json.dumps(sources, indent=2, default=str))

    # ── Query ──

    def list_tenants(self) -> List[str]:
        """List all tenants with stored logs."""
        base = Path(self.base_path)
        if not base.exists():
            return []
        return [d.name for d in base.iterdir() if d.is_dir()]

    def list_accounts(self, tenant_id: str, csp: str = "") -> List[Dict]:
        """List accounts with stored logs for a tenant."""
        base = Path(self.base_path) / tenant_id
        if not base.exists():
            return []
        accounts = []
        for csp_dir in base.iterdir():
            if not csp_dir.is_dir():
                continue
            if csp and csp_dir.name != csp:
                continue
            for acct_dir in csp_dir.iterdir():
                if acct_dir.is_dir():
                    state = self.get_collection_state(tenant_id, csp_dir.name, acct_dir.name)
                    accounts.append({
                        "tenant_id": tenant_id,
                        "csp": csp_dir.name,
                        "account_id": acct_dir.name,
                        "source_types": list(state.keys()),
                        "last_collection": state,
                    })
        return accounts

    def get_storage_stats(self, tenant_id: str) -> Dict:
        """Get storage usage stats for a tenant."""
        base = Path(self.base_path) / tenant_id
        if not base.exists():
            return {"total_files": 0, "total_bytes": 0}

        total_files = 0
        total_bytes = 0
        by_source = {}

        for f in base.rglob("*.json.gz"):
            total_files += 1
            total_bytes += f.stat().st_size
            # Determine source type from path
            parts = f.relative_to(base).parts
            if len(parts) >= 3:
                source_type = parts[2]  # tenant/csp/account/SOURCE_TYPE/...
                by_source[source_type] = by_source.get(source_type, 0) + f.stat().st_size

        return {
            "total_files": total_files,
            "total_bytes": total_bytes,
            "total_mb": round(total_bytes / 1024 / 1024, 2),
            "by_source": by_source,
        }
