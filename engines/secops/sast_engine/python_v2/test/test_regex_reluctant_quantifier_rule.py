# Noncompliant: Reluctant quantifier followed by an expression that can match the empty string
import re
pattern = re.compile(r'.*?.*')

# Compliant: Reluctant quantifier followed by an expression that can't match the empty string
pattern_ok = re.compile(r'.*?abc')

# Compliant: No reluctant quantifier
pattern_ok2 = re.compile(r'.*abc')
