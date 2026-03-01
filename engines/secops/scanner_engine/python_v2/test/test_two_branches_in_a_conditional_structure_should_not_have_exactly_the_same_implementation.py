# Test for: two_branches_in_a_conditional_structure_should_not_have_exactly_the_same_implementation
# This should trigger the rule for duplicate implementations in conditional branches

def test_duplicate_branches(x):
    if x == 1:
        print('duplicate')
    elif x == 2:
        print('duplicate')  # Noncompliant: duplicate implementation

# Compliant: different implementations
def test_unique_branches(x):
    if x == 1:
        print('one')
    elif x == 2:
        print('two')
