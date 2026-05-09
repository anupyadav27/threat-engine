"""GCP CIEM provider — parsers, readers, and session creation."""

import logging
from typing import Any, Dict, Optional, Type

from .base import BaseCIEMProvider

logger = logging.getLogger(__name__)


class GCPCIEMProvider(BaseCIEMProvider):
    def get_parsers(self) -> Dict[str, Type]:
        extra: Dict[str, Type] = {}
        try:
            from cdr_engine.parser.gcp_audit_parser import GCPAuditParser
            from cdr_engine.parser.gcp_flow_parser import GCPFlowParser
            extra["gcp_audit"] = GCPAuditParser
            extra["gcp_vpc_flow"] = GCPFlowParser
        except ImportError:
            pass
        return extra

    def get_readers(self) -> Dict[str, Type]:
        extra: Dict[str, Type] = {}
        try:
            from cdr_engine.reader.gcp_gcs_reader import GCPGCSReader
            extra["gcs"] = GCPGCSReader
        except ImportError:
            pass
        return extra

    def create_session(
        self,
        region: str,
        account_id: str,
        credentials: Optional[dict] = None,
    ) -> Optional[Any]:
        import json as _json

        creds = credentials or {}
        cred_type = creds.get("credential_type", "")
        try:
            from google.cloud import storage as gcs_storage

            if cred_type in ("service_account", "gcp_service_account", "service_account_key"):
                try:
                    import google.oauth2.service_account as sa_module

                    sa_info = creds.get("credentials") or creds.get("service_account_json")
                    if sa_info is None and creds.get("type") == "service_account":
                        sa_info = {k: v for k, v in creds.items()
                                   if k not in ("credential_type", "account_id", "created_at", "expires_at")}
                    if isinstance(sa_info, str):
                        sa_info = _json.loads(sa_info)
                    if sa_info:
                        gcp_creds = sa_module.Credentials.from_service_account_info(sa_info)
                        return gcs_storage.Client(
                            credentials=gcp_creds,
                            project=sa_info.get("project_id", account_id),
                        )
                except Exception as sa_exc:
                    logger.warning(f"GCP service account auth failed: {sa_exc}")

            # Fallback: ADC (pod workload identity / env GOOGLE_APPLICATION_CREDENTIALS)
            try:
                return gcs_storage.Client()
            except Exception as adc_exc:
                logger.warning(
                    f"GCP ADC session unavailable: {adc_exc} — "
                    "GCP log collection skipped (configure service_account credentials)"
                )
                return None

        except ImportError:
            logger.warning("google-cloud-storage not installed — GCP log collection unavailable")
            return None
