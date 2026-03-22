import re

# Noncompliant: Complex regex with multiple character classes and quantifiers
pattern1 = re.compile(r'[^a-zA-Z0-9_][^a-zA-Z0-9]')
pattern2 = re.compile(r'[a-zA-Z]+[0-9]+[_]+')
pattern3 = re.compile(r'([a-z]+)([0-9]+)')
pattern4 = re.compile(r'{[0-9]+}{[0-9]+}')
pattern5 = re.compile(r'[a-z][A-Z][0-9][_]{2,}[a-zA-Z]{3,}')

# Compliant: Simple regex
pattern6 = re.compile(r'[a-zA-Z0-9]')
pattern7 = re.compile(r'[a-z]+')
