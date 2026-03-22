import re

# Noncompliant: Contains empty named groups, should trigger the rule
pattern1 = re.compile(r'(?P<group1>)(?P<group2>)')
pattern2 = re.compile(r'(?P<empty>)|(?P<still_empty>)')

# Compliant: Named groups with content, should NOT trigger the rule
pattern3 = re.compile(r'(?P<group1>[a-z]+)(?P<group2>[0-9]+)')
pattern4 = re.compile(r'(?P<name>abc)')
