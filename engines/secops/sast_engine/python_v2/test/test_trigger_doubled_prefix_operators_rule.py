# Valid Python test script for doubled prefix operator rule
# Noncompliant: Chained comparison that may be confusing
x = 5
if x != 10 < 20:
    print("Confusing chained comparison")

# Compliant: Simple comparisons
if x != 10:
    print("Not equal, compliant")
if x < 20:
    print("Less than, compliant")
