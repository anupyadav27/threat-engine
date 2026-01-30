# Test for: replacement_strings_should_reference_existing_regular_expression_groups
import re

# Noncompliant: Replacement string does not reference a group
pattern = re.compile(r'(foo)(bar)')
result = pattern.sub('baz', 'foobar')  # Should trigger the rule

# Compliant: Replacement string references a group
pattern2 = re.compile(r'(foo)(bar)')
result2 = pattern2.sub(r'\1baz', 'foobar')  # Should NOT trigger the rule

# Compliant: Named group referenced
pattern3 = re.compile(r'(?P<foo>foo)(bar)')
result3 = pattern3.sub(r'\g<foo>baz', 'foobar')  # Should NOT trigger the rule

# Noncompliant: Replacement string is literal, no group reference
pattern4 = re.compile(r'(foo)(bar)')
result4 = pattern4.sub('barfoo', 'foobar')  # Should trigger the rule
