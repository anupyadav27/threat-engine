# Noncompliant: triggers checkpoints_should_be_used_instead_of_sleep0
import time

def test():
    time.sleep(2)  # Should trigger the rule

# Compliant: does not trigger
from unittest.mock import patch

@patch('time.sleep')
def test_with_checkpoint(mock_sleep):
    mock_sleep.return_value = 0
    # test logic
