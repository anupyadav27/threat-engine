# Test script to trigger the 'redundant_collection_functions_should_be_avoided' rule

def test_list_comprehension():
    # Noncompliant: should trigger the rule
    numbers = [x*x for x in range(10)]
    return numbers

def test_map_function():
    # Noncompliant: should trigger the rule
    numbers = list(map(lambda x: x*x, range(10)))
    return numbers

# Compliant example (should NOT trigger the rule)
def test_simple_loop():
    numbers = []
    for x in range(10):
        numbers.append(x*x)
    return numbers
