"""
AliCloud ActionTrail reader — queries the ActionTrail LookupEvents API directly.

No OSS or SLS bucket required. The API returns up to 90 days of audit events
for all regions in the account, paginated via NextToken.

Session dict (from AliCloudCIEMProvider.create_session):
    {"access_key_id": "...", "access_key_secret": "...", "region": "cn-hangzhou"}

Storage type: alicloud_actiontrail
source.location: AliCloud region ID (e.g. "cn-hangzhou")
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List

from .base_reader import BaseReader, LogSource

logger = logging.getLogger(__name__)

_BATCH_SIZE = 50    # ActionTrail LookupEvents max per page (API limit: 1-50)
_MAX_PAGES  = 2000  # safety cap — 2000 × 50 = 100k events


class AliCloudActionTrailReader(BaseReader):
    """Read AliCloud ActionTrail events via the LookupEvents API."""

    storage_type = "alicloud_actiontrail"

    def list_log_files(
        self,
        session: Any,
        source: LogSource,
        start_time: datetime,
        end_time: datetime,
    ) -> List[Dict[str, Any]]:
        """ActionTrail returns events directly — no file listing needed."""
        return [{"key": f"actiontrail:{source.location}:{start_time.isoformat()}", "size": 0, "last_modified": end_time}]

    def read(
        self,
        session: Any,
        source: LogSource,
        start_time: datetime,
        end_time: datetime,
        max_bytes: int = 500_000_000,
    ) -> Generator[bytes, None, None]:
        """Yield batches of ActionTrail events as JSON bytes (list-of-dicts per yield)."""
        if not isinstance(session, dict):
            logger.error("AliCloudActionTrailReader: session must be a dict with access_key_id/secret")
            return

        access_key_id     = session.get("access_key_id", "")
        access_key_secret = session.get("access_key_secret", "")
        region            = source.location or session.get("region", "cn-hangzhou")

        if not access_key_id or not access_key_secret:
            logger.error("AliCloudActionTrailReader: missing access_key_id or access_key_secret")
            return

        try:
            from aliyunsdkcore.client import AcsClient
            from aliyunsdkcore.request import CommonRequest
            from aliyunsdkcore.acs_exception.exceptions import ClientException, ServerException
        except ImportError:
            logger.error("aliyunsdkcore not installed — cannot read ActionTrail. Add aliyun-python-sdk-core to requirements.")
            return

        try:
            client = AcsClient(ak=access_key_id, secret=access_key_secret, region_id=region)
        except Exception as exc:
            logger.error(f"AliCloud client creation failed: {exc}")
            return

        start_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_str   = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        total_events = 0
        total_bytes  = 0
        next_token   = None

        for page in range(_MAX_PAGES):
            try:
                request = CommonRequest()
                request.set_domain(f"actiontrail.{region}.aliyuncs.com")
                request.set_version("2020-07-06")
                request.set_action_name("LookupEvents")
                request.set_method("POST")
                request.add_query_param("StartTime",  start_str)
                request.add_query_param("EndTime",    end_str)
                request.add_query_param("MaxResults", _BATCH_SIZE)
                if next_token:
                    request.add_query_param("NextToken", next_token)

                raw = client.do_action_with_exception(request)
                result = json.loads(raw)
            except (ClientException, ServerException) as exc:
                logger.warning(f"ActionTrail API error (region={region}): {exc}")
                break
            except Exception as exc:
                logger.warning(f"ActionTrail request failed: {exc}")
                break

            events = result.get("Events", [])
            if not events:
                break

            batch_bytes = json.dumps(events).encode("utf-8")
            total_events += len(events)
            total_bytes  += len(batch_bytes)
            yield batch_bytes

            if total_bytes >= max_bytes:
                logger.info(f"AliCloud ActionTrail: hit max_bytes ({max_bytes})")
                break

            next_token = result.get("NextToken")
            if not next_token:
                break

        logger.info(
            f"AliCloud ActionTrail reader: {total_events} events from {region} "
            f"({total_bytes / 1024:.1f} KB)"
        )
