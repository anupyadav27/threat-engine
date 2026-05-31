"""AliCloud CIEM provider — ActionTrail audit log collection."""

import json
import logging
import os
from typing import Any, Dict, Optional, Type

import boto3

from .base import BaseCIEMProvider

logger = logging.getLogger(__name__)


class AliCloudCIEMProvider(BaseCIEMProvider):
    """AliCloud uses ActionTrail for audit logs, queried via the LookupEvents API."""

    def get_parsers(self) -> Dict[str, Type]:
        from cdr_engine.parser.actiontrail_parser import ActionTrailParser
        return {
            "alicloud_actiontrail": ActionTrailParser,
        }

    def get_readers(self) -> Dict[str, Type]:
        from cdr_engine.reader.alicloud_actiontrail_reader import AliCloudActionTrailReader
        return {
            "alicloud_actiontrail": AliCloudActionTrailReader,
        }

    def create_session(
        self,
        region: str,
        account_id: str,
        credentials: Optional[Dict] = None,
    ) -> Optional[Any]:
        """Return a credentials dict for AliCloud API calls.

        Tries (in order):
          1. credentials dict passed in (already fetched from Secrets Manager)
          2. AWS Secrets Manager via credential_ref from env
          3. Env vars ALICLOUD_ACCESS_KEY_ID / ALICLOUD_ACCESS_KEY_SECRET

        Returns:
            dict with access_key_id, access_key_secret, region
        """
        # 1. From credentials dict (standard CIEM flow — run_scan.py fetches from SM)
        if credentials:
            ak = credentials.get("access_key_id") or credentials.get("AccessKeyId")
            sk = credentials.get("access_key_secret") or credentials.get("AccessKeySecret") or credentials.get("access_key_id_secret")
            region_from_creds = credentials.get("region", region or "cn-hangzhou")
            if ak and sk:
                return {"access_key_id": ak, "access_key_secret": sk, "region": region_from_creds}

        # 2. From Secrets Manager via account_id-derived secret name
        secret_name = f"threat-engine/account/{account_id}"
        try:
            sm = boto3.client("secretsmanager", region_name="ap-south-1")
            resp = sm.get_secret_value(SecretId=secret_name)
            creds = json.loads(resp["SecretString"])
            ak = creds.get("access_key_id") or creds.get("AccessKeyId")
            sk = creds.get("access_key_secret") or creds.get("AccessKeySecret")
            region_from_sm = creds.get("region", region or "cn-hangzhou")
            if ak and sk:
                logger.info(f"AliCloud credentials loaded from Secrets Manager: {secret_name}")
                return {"access_key_id": ak, "access_key_secret": sk, "region": region_from_sm}
        except Exception as exc:
            logger.warning(f"Could not load AliCloud credentials from Secrets Manager ({secret_name}): {exc}")

        # 3. Environment variable fallback
        ak = os.getenv("ALICLOUD_ACCESS_KEY_ID")
        sk = os.getenv("ALICLOUD_ACCESS_KEY_SECRET")
        if ak and sk:
            logger.info("AliCloud credentials loaded from environment variables")
            return {"access_key_id": ak, "access_key_secret": sk, "region": region or "cn-hangzhou"}

        logger.error(f"AliCloud CIEM: no credentials found for account {account_id}")
        return None
