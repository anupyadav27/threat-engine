# Test to trigger 'a_reason_should_be_provided_when_skipping_a_test' rule
import unittest

def test_should_trigger_rule():
    unittest.skip()

# Compliant example (should NOT trigger the rule)
def test_should_not_trigger_rule():
    unittest.skip('Skipping this test due to a known issue')
