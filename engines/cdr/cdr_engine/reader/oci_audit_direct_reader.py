"""
OCI Audit Direct Reader — queries the OCI Audit API directly.

No Object Storage bucket required. Uses oci.audit.AuditClient.list_events()
to fetch audit events per compartment. Defaults to querying at tenancy root
(which captures all compartments when called with the tenancy OCID).

Session dict (from OCICIEMProvider.create_session):
    {"config": oci_config_dict, "signer": optional_signer}

storage_type: oci_audit_direct
source.location: OCI region (e.g. "ap-mumbai-1")
"""

import json
import logging
import tempfile
import os
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List

from .base_reader import BaseReader, LogSource

logger = logging.getLogger(__name__)

_PAGE_LIMIT = 500   # OCI Audit API max per page


class OCIAuditDirectReader(BaseReader):
    """Read OCI Audit events directly via the OCI Audit API."""

    storage_type = "oci_audit_direct"

    def list_log_files(
        self,
        session: Any,
        source: LogSource,
        start_time: datetime,
        end_time: datetime,
    ) -> List[Dict[str, Any]]:
        """OCI Audit returns events directly — no file listing needed."""
        return [{"key": f"oci_audit:{source.location}:{start_time.isoformat()}", "size": 0, "last_modified": end_time}]

    def read(
        self,
        session: Any,
        source: LogSource,
        start_time: datetime,
        end_time: datetime,
        max_bytes: int = 500_000_000,
    ) -> Generator[bytes, None, None]:
        """Yield batches of OCI Audit events as JSON bytes (list-of-dicts per yield)."""
        try:
            import oci
        except ImportError:
            logger.error("oci SDK not installed — cannot read OCI Audit. Run: pip install oci")
            return

        if not isinstance(session, dict):
            logger.error("OCIAuditDirectReader: session must be a dict with 'config' key")
            return

        config = dict(session.get("config", {}))
        signer = session.get("signer")

        # Use source.location as the OCI region — overrides run_scan's AWS region fallback
        oci_region = source.location or config.get("region", "ap-mumbai-1")
        config["region"] = oci_region

        # Build OCI config — may need to write private_key to temp file
        _tmp_key = None
        if config.get("key_content") and not config.get("key_file"):
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False)
            tmp.write(config.pop("key_content"))
            tmp.close()
            _tmp_key = tmp.name
            config["key_file"] = _tmp_key

        tenancy_ocid = config.get("tenancy", "")
        if not tenancy_ocid:
            logger.error("OCIAuditDirectReader: no tenancy OCID in config")
            if _tmp_key:
                os.unlink(_tmp_key)
            return

        try:
            if signer:
                client = oci.audit.AuditClient(config={}, signer=signer)
            else:
                client = oci.audit.AuditClient(config)
        except Exception as exc:
            logger.error(f"OCI Audit client creation failed: {exc}")
            if _tmp_key:
                os.unlink(_tmp_key)
            return

        total_events = 0
        total_bytes = 0
        page = None

        try:
            while True:
                kwargs = {
                    "compartment_id": tenancy_ocid,
                    "start_time": start_time,
                    "end_time": end_time,
                }
                if page:
                    kwargs["page"] = page

                try:
                    resp = client.list_events(**kwargs)
                except Exception as exc:
                    logger.warning(f"OCI Audit API error (region={source.location}): {exc}")
                    break

                events = resp.data
                if not events:
                    break

                # Use oci.util.to_dict for safe recursive serialization of OCI model objects
                try:
                    from oci.util import to_dict as oci_to_dict
                    batch = [oci_to_dict(e) for e in events]
                except Exception:
                    # Fallback: manual extraction
                    batch = []
                    for e in events:
                        try:
                            batch.append({
                                "eventType": getattr(e, "event_type", ""),
                                "source": getattr(e, "source", ""),
                                "eventTime": e.event_time.isoformat() if getattr(e, "event_time", None) else "",
                                "data": vars(e.data) if getattr(e, "data", None) else {},
                            })
                        except Exception:
                            continue

                if batch:
                    batch_bytes = json.dumps(batch).encode("utf-8")
                    total_events += len(batch)
                    total_bytes += len(batch_bytes)
                    yield batch_bytes

                    if total_bytes >= max_bytes:
                        logger.info(f"OCI Audit: hit max_bytes ({max_bytes})")
                        break

                next_page = resp.headers.get("opc-next-page") if resp.headers else None
                if not next_page:
                    break
                page = next_page

        finally:
            if _tmp_key and os.path.exists(_tmp_key):
                os.unlink(_tmp_key)

        logger.info(
            f"OCI Audit direct reader: {total_events} events from {source.location} "
            f"({total_bytes / 1024:.1f} KB)"
        )
