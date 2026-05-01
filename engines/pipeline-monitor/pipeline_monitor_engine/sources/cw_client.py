"""
CloudWatch Logs Insights client.

All queries target the /threat-engine/engines log group (written by Fluent-bit).
Results are paginated and returned as plain dicts for the API layer.
"""

import logging
import time
from typing import Any, Dict, List, Optional

import boto3

logger = logging.getLogger(__name__)

import os

LOG_GROUP_ENGINES = "/threat-engine/engines"
LOG_GROUP_ARGO    = "/threat-engine/argo"
REGION            = os.environ.get("AWS_REGION", "us-east-1")

# Pre-built CW Insights query templates for admin portal
QUERY_TEMPLATES = {
    # All ERROR lines for a specific scan_run_id across all engines
    "errors_by_scan": """
        fields @timestamp, @logStream, level, scan_run_id, @message
        | filter level = "ERROR"
        | filter scan_run_id = "{scan_run_id}"
        | sort @timestamp asc
        | limit 500
    """,

    # All WARN/ERROR for a tenant across any scan
    "issues_by_tenant": """
        fields @timestamp, @logStream, level, scan_run_id, @message
        | filter level in ["ERROR", "WARNING"]
        | filter @logStream like "{tenant_id}"
        | sort @timestamp desc
        | limit 500
    """,

    # Error/warning counts per engine over a time window
    "error_rate_by_engine": """
        fields @logStream, level
        | filter level in ["ERROR", "WARNING"]
        | stats count(*) as count by @logStream, level
        | sort count desc
        | limit 50
    """,

    # Full chronological log timeline for a scan (all levels)
    "scan_timeline": """
        fields @timestamp, @logStream, level, scan_run_id, @message
        | filter scan_run_id = "{scan_run_id}"
        | sort @timestamp asc
        | limit 1000
    """,

    # Recent unique error patterns (deduped by message prefix)
    "recent_error_patterns": """
        fields @timestamp, @logStream, @message
        | filter level = "ERROR"
        | stats count(*) as occurrences, latest(@timestamp) as last_seen
            by substr(@message, 0, 120)
        | sort occurrences desc
        | limit 30
    """,

    # Slow scans: engines taking longer than threshold
    "slow_engines": """
        fields @timestamp, @logStream, @message
        | filter @message like "COMPLETE" or @message like "completed"
        | parse @message /(?<duration_s>\\d+\\.?\\d*)s/
        | stats avg(duration_s) as avg_s, max(duration_s) as max_s by @logStream
        | sort max_s desc
        | limit 20
    """,
}


def _run_insights_query(
    query: str,
    start_time: int,
    end_time: int,
    log_groups: Optional[List[str]] = None,
    max_wait_s: int = 30,
) -> List[Dict[str, Any]]:
    """Run a CW Insights query and poll until complete. Returns list of result records."""
    logs = boto3.client("logs", region_name=REGION)
    groups = log_groups or [LOG_GROUP_ENGINES]

    resp = logs.start_query(
        logGroupNames=groups,
        startTime=start_time,
        endTime=end_time,
        queryString=query,
        limit=1000,
    )
    query_id = resp["queryId"]

    # Poll until complete (max_wait_s)
    waited = 0
    while waited < max_wait_s:
        result = logs.get_query_results(queryId=query_id)
        status = result["status"]
        if status == "Complete":
            return _flatten_results(result["results"])
        if status in ("Failed", "Cancelled", "Timeout"):
            logger.error("CW Insights query %s: %s", query_id, status)
            return []
        time.sleep(1)
        waited += 1

    # Cancel the query if still running
    try:
        logs.stop_query(queryId=query_id)
    except Exception:
        pass
    logger.warning("CW Insights query timed out after %ds", max_wait_s)
    return []


def _flatten_results(results: list) -> List[Dict[str, Any]]:
    """Convert CW Insights [{field, value}] format to plain dicts."""
    return [
        {item["field"]: item["value"] for item in row}
        for row in results
    ]


def _time_range(hours_back: int = 24):
    now = int(time.time())
    return now - hours_back * 3600, now


# ── Public query functions ────────────────────────────────────────────────────

def query_errors_by_scan(scan_run_id: str, hours_back: int = 48) -> List[Dict[str, Any]]:
    start, end = _time_range(hours_back)
    q = QUERY_TEMPLATES["errors_by_scan"].format(scan_run_id=scan_run_id)
    return _run_insights_query(q, start, end)


def query_issues_by_tenant(tenant_id: str, hours_back: int = 24) -> List[Dict[str, Any]]:
    start, end = _time_range(hours_back)
    q = QUERY_TEMPLATES["issues_by_tenant"].format(tenant_id=tenant_id)
    return _run_insights_query(q, start, end)


def query_error_rate_by_engine(hours_back: int = 24) -> List[Dict[str, Any]]:
    start, end = _time_range(hours_back)
    return _run_insights_query(QUERY_TEMPLATES["error_rate_by_engine"], start, end)


def query_scan_timeline(scan_run_id: str, hours_back: int = 48) -> List[Dict[str, Any]]:
    start, end = _time_range(hours_back)
    q = QUERY_TEMPLATES["scan_timeline"].format(scan_run_id=scan_run_id)
    return _run_insights_query(q, start, end)


def query_recent_error_patterns(hours_back: int = 24) -> List[Dict[str, Any]]:
    start, end = _time_range(hours_back)
    return _run_insights_query(QUERY_TEMPLATES["recent_error_patterns"], start, end)


def query_slow_engines(hours_back: int = 168) -> List[Dict[str, Any]]:  # 7 days
    start, end = _time_range(hours_back)
    return _run_insights_query(QUERY_TEMPLATES["slow_engines"], start, end)


def run_custom_query(
    query: str,
    hours_back: int = 24,
    log_groups: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Run an arbitrary CW Insights query — for power users in admin portal."""
    start, end = _time_range(hours_back)
    return _run_insights_query(query, start, end, log_groups=log_groups)
