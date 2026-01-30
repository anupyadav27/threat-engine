import logging

# This should trigger the rule: logging.basicConfig(level=logging.DEBUG)
logging.basicConfig(level=logging.DEBUG)

# This should NOT trigger the rule (compliant example)
logging.basicConfig(level=logging.WARNING)
