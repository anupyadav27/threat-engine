
# Test for repeated patterns in regular expressions that match empty string
import re

# Noncompliant: Uses * quantifier which can match empty string
regex = re.compile(r'(a|b)*')  # Should trigger - * can match empty string
matches = regex.findall('')  # Testing with empty string to demonstrate issue

# Noncompliant: Uses ? quantifier which can match empty string
regex2 = re.compile(r'(x|y)?')  # Should trigger - ? can match empty string
matches2 = regex2.findall('')

# Compliant: Uses + quantifier which cannot match empty string
regex_ok = re.compile(r'(a|b)+')  # Should not trigger - + requires at least one match
matches_ok = regex_ok.findall('')
