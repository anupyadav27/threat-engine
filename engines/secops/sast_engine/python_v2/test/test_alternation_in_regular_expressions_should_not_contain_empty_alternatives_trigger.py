# Minimal test to trigger: alternation_in_regular_expressions_should_not_contain_empty_alternatives
import re

# Noncompliant: trailing empty alternative (empty alternative after the '|')
pattern = re.compile('a|')

# Keep the file minimal to avoid triggering unrelated rules
