# Test script to trigger the 'recursion_should_not_be_infinite' rule

def infinite_recursion():
    # Noncompliant: should trigger the rule
    infinite_recursion()

# Compliant example (should NOT trigger the rule)
def finite_recursion(some_condition):
    if some_condition:
        finite_recursion(False)
    else:
        pass
