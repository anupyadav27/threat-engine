"""OCI CIEM provider — parsers, readers, and session creation."""

import logging
import os
from typing import Any, Dict, Optional, Type

from .base import BaseCIEMProvider

logger = logging.getLogger(__name__)


class OCICIEMProvider(BaseCIEMProvider):
    def get_parsers(self) -> Dict[str, Type]:
        extra: Dict[str, Type] = {}
        try:
            from cdr_engine.parser.oci_audit_parser import OCIAuditParser
            extra["oci_audit"] = OCIAuditParser
            extra["oci_audit_direct"] = OCIAuditParser  # same format, different delivery
        except ImportError:
            pass
        return extra

    def get_readers(self) -> Dict[str, Type]:
        extra: Dict[str, Type] = {}
        try:
            from cdr_engine.reader.oci_os_reader import OCIObjectStorageReader
            extra["oci_os"] = OCIObjectStorageReader
        except ImportError:
            pass
        try:
            from cdr_engine.reader.oci_audit_direct_reader import OCIAuditDirectReader
            extra["oci_audit_direct"] = OCIAuditDirectReader
        except ImportError:
            pass
        return extra

    def create_session(
        self,
        region: str,
        account_id: str,
        credentials: Optional[dict] = None,
    ) -> Optional[Any]:
        creds = credentials or {}
        cred_type = creds.get("credential_type", "")
        try:
            import oci

            if cred_type in ("api_key", "oci_api_key") and creds.get("private_key"):
                # Return as {"config": {...}} so both OS and direct readers work
                return {
                    "config": {
                        "tenancy": creds.get("tenancy_ocid", creds.get("tenancy", "")),
                        "user": creds.get("user_ocid", creds.get("user", "")),
                        "fingerprint": creds.get("fingerprint", ""),
                        "key_content": creds.get("private_key", ""),
                        "region": region or creds.get("region", os.getenv("OCI_REGION", "ap-mumbai-1")),
                    }
                }

            # Fallback: ~/.oci/config or environment
            if os.path.exists(os.path.expanduser("~/.oci/config")):
                return {"config": oci.config.from_file()}

            return {
                "config": {
                    "tenancy": os.getenv("OCI_TENANCY", ""),
                    "user": os.getenv("OCI_USER", ""),
                    "fingerprint": os.getenv("OCI_FINGERPRINT", ""),
                    "key_file": os.getenv("OCI_KEY_FILE", ""),
                    "region": region or os.getenv("OCI_REGION", ""),
                }
            }
        except ImportError:
            logger.warning("oci SDK not installed — OCI log collection unavailable")
            return None
