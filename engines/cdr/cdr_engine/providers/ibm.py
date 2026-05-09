"""IBM CIEM provider — parsers, readers, and session creation."""

import logging
import os
from typing import Any, Dict, Optional, Type

from .base import BaseCIEMProvider

logger = logging.getLogger(__name__)


class IBMCIEMProvider(BaseCIEMProvider):
    def get_parsers(self) -> Dict[str, Type]:
        extra: Dict[str, Type] = {}
        try:
            from cdr_engine.parser.ibm_activity_parser import IBMActivityParser
            extra["ibm_activity"] = IBMActivityParser
        except ImportError:
            pass
        return extra

    def get_readers(self) -> Dict[str, Type]:
        extra: Dict[str, Type] = {}
        try:
            from cdr_engine.reader.ibm_cos_reader import IBMCOSReader
            extra["ibm_cos"] = IBMCOSReader
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

        if cred_type in ("api_key", "ibm_api_key") and creds.get("api_key"):
            return {
                "api_key": creds.get("api_key", ""),
                "service_instance_id": creds.get("cos_instance_id", creds.get("service_instance_id", "")),
                "endpoint": creds.get(
                    "cos_endpoint",
                    os.getenv("IBM_COS_ENDPOINT", "https://s3.us-south.cloud-object-storage.appdomain.cloud"),
                ),
            }

        # Fallback: environment variables
        return {
            "api_key": os.getenv("IBM_API_KEY", ""),
            "service_instance_id": os.getenv("IBM_COS_INSTANCE_ID", ""),
            "endpoint": os.getenv(
                "IBM_COS_ENDPOINT",
                "https://s3.us-south.cloud-object-storage.appdomain.cloud",
            ),
        }
