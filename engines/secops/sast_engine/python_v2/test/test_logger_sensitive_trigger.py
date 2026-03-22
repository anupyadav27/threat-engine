import logging

logger = logging.getLogger(__name__)

# This should trigger the rule: forbidden value 'password' in log message
logger.error("User password: {password}")

# These should NOT trigger the rule
logger.error("Unauthorized access attempt")
logger.info("User logged in successfully")
