# Noncompliant: walrus operator in a complex expression
result = [i for i in range(10)] if (x := sum(range(5))) > 5 else []

# Compliant: walrus operator used simply
x = sum(range(5))
if x > 5:
    result = [i for i in range(10)]
else:
    result = []
