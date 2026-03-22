# Test script to trigger comprehensions_should_be_used_instead_of_constructors_around_generator_expressions
# Noncompliant example: triggers the rule
lst = list(x for x in range(10) if x % 2 == 0)  # Should trigger the rule

# Compliant example: should NOT trigger the rule
lst2 = [x for x in range(10) if x % 2 == 0]
