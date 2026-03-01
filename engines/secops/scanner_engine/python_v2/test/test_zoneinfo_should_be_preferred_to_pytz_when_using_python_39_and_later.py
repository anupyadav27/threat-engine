# Test for zoneinfo_should_be_preferred_to_pytz_when_using_python_39_and_later rule
# This should trigger the rule by importing pytz
import pytz
from pytz import timezone

def use_timezone():
    tz = timezone('UTC')
    return tz
