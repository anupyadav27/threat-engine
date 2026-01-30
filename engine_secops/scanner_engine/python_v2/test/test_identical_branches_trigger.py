# Test script to trigger 'all_branches_in_a_conditional_structure_should_not_have_exactly_the_same_implementation'

def test_identical_branches():
    x = 5
    if x > 10:
        y = 20  # Noncompliant: identical implementation
    else:
        y = 20  # Noncompliant: identical implementation
    return y

def test_different_branches():
    x = 5
    if x > 10:
        y = 20
    else:
        y = x + 5  # Compliant: different implementation
    return y
