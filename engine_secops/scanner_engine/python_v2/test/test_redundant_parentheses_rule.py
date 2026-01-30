# Test script to trigger the 'redundant_pairs_of_parentheses_should_be_removed' rule

def test_redundant_parentheses():
    # Noncompliant: should trigger the rule
    x = (1 + (2 - 3)) * 4
    return x

# Compliant example (should NOT trigger the rule)
def test_no_redundant_parentheses():
    x = 1 + 2 * 4
    return x
