# Noncompliant example: static key in dictionary comprehension
result = {42: value for value in range(5)}

# Compliant example: variable key in dictionary comprehension
result2 = {key: value for key, value in enumerate(range(5))}
