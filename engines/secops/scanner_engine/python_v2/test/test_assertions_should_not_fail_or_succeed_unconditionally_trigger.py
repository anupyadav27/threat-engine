#!/usr/bin/env python3
"""
Test script to trigger the "assertions_should_not_fail_or_succeed_unconditionally" rule.

This script contains various assert statements that should trigger the rule,
including unconditional assertions with hardcoded True and False values.
"""

def test_unconditional_assertions():
    """Function with unconditional assertions that should trigger the rule."""
    
    # These assertions should trigger the rule (hardcoded True/False)
    assert True  # Rule violation: unconditional success
    assert False  # Rule violation: unconditional failure
    
    # More examples that should trigger the rule
    assert True, "This will always pass"
    assert False, "This will always fail"
    
    # Nested conditions that still use hardcoded values
    if True:
        assert True  # Rule violation
    
    if False:
        assert False  # Rule violation


def test_conditional_assertions():
    """Function with proper conditional assertions that should NOT trigger the rule."""
    
    # These assertions should NOT trigger the rule (proper conditions)
    x = 5
    y = 10
    
    assert x < y  # Good: proper condition
    assert x == 5  # Good: proper condition
    assert isinstance(x, int)  # Good: proper condition
    assert len("hello") == 5  # Good: proper condition
    
    # Complex conditions
    assert x > 0 and y > 0  # Good: complex condition
    assert not (x > y)  # Good: negated condition


def test_mixed_assertions():
    """Function with mixed assertions - some good, some bad."""
    
    value = "test"
    
    # Good assertions
    assert value == "test"
    assert len(value) > 0
    
    # Bad assertions that should trigger the rule
    assert True  # Rule violation
    assert False  # Rule violation
    
    # More good assertions
    assert isinstance(value, str)
    assert value.startswith("t")


class TestClass:
    """Class with assertion examples."""
    
    def __init__(self):
        self.value = 42
        
        # Bad assertion in constructor
        assert True  # Rule violation
    
    def validate(self):
        """Method with validation assertions."""
        
        # Good assertions
        assert self.value > 0
        assert isinstance(self.value, int)
        
        # Bad assertion
        assert False  # Rule violation
        
        return True


def test_edge_cases():
    """Test edge cases for the assertion rule."""
    
    # Assertions with constants that evaluate to True/False
    assert True  # Rule violation: direct True
    assert False  # Rule violation: direct False
    
    # Boolean variables (these should NOT trigger the rule)
    is_valid = True
    is_empty = False
    
    assert is_valid  # Good: using variable
    assert not is_empty  # Good: using variable with negation


if __name__ == "__main__":
    # This section would normally run tests, but contains rule violations
    
    print("Running test functions...")
    
    # More rule violations in main execution
    assert True  # Rule violation
    
    try:
        test_unconditional_assertions()
    except AssertionError:
        pass
    
    try:
        test_conditional_assertions()
        print("Conditional assertions passed")
    except AssertionError:
        print("Conditional assertions failed")
    
    try:
        test_mixed_assertions()
    except AssertionError:
        pass
    
    # Final unconditional assertion
    assert False  # Rule violation