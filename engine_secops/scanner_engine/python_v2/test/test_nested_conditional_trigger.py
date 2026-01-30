# Test script to trigger conditional_expressions_should_not_be_nested
# Noncompliant example: triggers the rule
x = 15
y = 7
if x > 10:
    if y > 5:
        print("Nested If - should trigger")
    else:
        print("Inner else")
else:
    print("Outer else")

# Compliant example: should NOT trigger the rule
if x > 10:
    print(y > 5)
else:
    print("Outer else")
