# Test for: return_and_yield_should_not_be_used_in_the_same_function

def bad_function():
    yield 1
    return 2  # Should trigger the rule

def good_function_yield():
    yield 1  # Should NOT trigger the rule

def good_function_return():
    return 2  # Should NOT trigger the rule
