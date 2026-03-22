# Noncompliant: using list() in iteration
for i in list(range(10)):
    print(i)

# Compliant: direct iteration
for i in range(10):
    print(i)

# Compliant: list comprehension
squared = [i*i for i in range(10)]
