# Minimal test to trigger: alternatives_in_regular_expressions_should_be_grouped_when_used_with_anchors
import re

# Noncompliant: alternatives with anchors, not grouped
pattern = re.compile('^(abc|def)$')

# Keep the file minimal to avoid triggering unrelated rules
