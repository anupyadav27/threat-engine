# Noncompliant: Duplicate conditions in related if statements
x = 7
if x > 5:
    print('x is greater than 5')
if x > 5:
    print('x is still greater than 5')

# Compliant: Different conditions
if x > 5:
    print('x is greater than 5')
if x <= 10:
    print('x is less than or equal to 10')
