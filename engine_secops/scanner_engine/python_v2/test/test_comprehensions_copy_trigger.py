# Test script to trigger comprehensions_only_used_to_copy_should_be_replaced_with_the_respective_constructor_calls
# Noncompliant example: triggers the rule
b = [1, 2, 3]
a = [i for i in b]  # Should trigger the rule

# Compliant example: should NOT trigger the rule
a2 = list(b)
