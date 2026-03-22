import re

# Noncompliant: Missing raw string prefix, should trigger the rule
pattern1 = re.compile('[0-9]+')

# Compliant: Has raw string prefix, should NOT trigger the rule
pattern2 = re.compile(r'[0-9]+')

# Noncompliant: Missing raw string prefix with brackets
pattern3 = re.compile('[a-zA-Z]+')

# Compliant: Has raw string prefix with brackets
pattern4 = re.compile(r'[a-zA-Z]+')
