# Noncompliant: should trigger comparison_to_none_should_not_be_constant
x = 5
if x != None:
    print("x is not None")

# Compliant: should NOT trigger
some_var = None
if some_var != x:
    print("some_var is not x")
