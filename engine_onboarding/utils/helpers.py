"""
Helper utility functions
"""
import uuid
from datetime import datetime, timedelta
from croniter import croniter
import pytz


def generate_external_id() -> str:
    """Generate unique external ID for AWS role assumption"""
    return f"threat-engine-{uuid.uuid4().hex[:16]}"


def is_valid_cron(cron_expression: str) -> bool:
    """Validate cron expression"""
    try:
        croniter(cron_expression)
        return True
    except Exception:
        return False


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
    tz = pytz.timezone(timezone)
    now = datetime.now(tz)
    
    if schedule_type == 'cron' and cron_expression:
        cron = croniter(cron_expression, now)
        next_run = cron.get_next(datetime)
        return next_run.astimezone(pytz.UTC).replace(tzinfo=None)
    
    elif schedule_type == 'interval' and interval_seconds:
        next_run = now + timedelta(seconds=interval_seconds)
        return next_run.astimezone(pytz.UTC).replace(tzinfo=None)
    
    elif schedule_type == 'one_time':
        return None
    
    return None


# Common cron patterns
CRON_PATTERNS = {
    "hourly": "0 * * * *",
    "daily": "0 2 * * *",  # 2 AM daily
    "weekly": "0 2 * * 0",  # 2 AM Sunday
    "monthly": "0 2 1 * *",  # 2 AM 1st of month
    "every_6_hours": "0 */6 * * *",
    "every_12_hours": "0 */12 * * *"
}

