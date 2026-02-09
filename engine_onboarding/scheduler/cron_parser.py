"""
Cron expression parsing and validation
"""
from datetime import datetime
from typing import List
from croniter import croniter
import pytz


def is_valid_cron(cron_expression: str) -> bool:
    """Validate cron expression"""
    try:
        croniter(cron_expression)
        return True
    except Exception:
        return False


def get_next_runs(cron_expression: str, count: int = 5) -> List[datetime]:
    """Get next N run times"""
    cron = croniter(cron_expression, datetime.now())
    return [cron.get_next(datetime) for _ in range(count)]


def calculate_next_run_time(
    schedule_type: str,
    cron_expression: str = None,
    interval_seconds: int = None,
    timezone: str = 'UTC'
) -> datetime:
    """
    Calculate next run time based on schedule type
    
    Args:
        schedule_type: 'cron', 'interval', or 'one_time'
        cron_expression: Cron expression (for cron type)
        interval_seconds: Interval in seconds (for interval type)
        timezone: Timezone string
        
    Returns:
        Next run datetime or None for one_time
    """
    from engine_onboarding.utils.helpers import calculate_next_run_time as helper_calc
    return helper_calc(schedule_type, cron_expression, interval_seconds, timezone)


# Common cron patterns
CRON_PATTERNS = {
    "hourly": "0 * * * *",
    "daily": "0 2 * * *",  # 2 AM daily
    "weekly": "0 2 * * 0",  # 2 AM Sunday
    "monthly": "0 2 1 * *",  # 2 AM 1st of month
    "every_6_hours": "0 */6 * * *",
    "every_12_hours": "0 */12 * * *"
}

