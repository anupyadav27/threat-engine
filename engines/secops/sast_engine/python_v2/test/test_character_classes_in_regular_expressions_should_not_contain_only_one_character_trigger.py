# Noncompliant: triggers character_classes_in_regular_expressions_should_not_contain_only_one_character
import re
pattern1 = re.compile(r'[A]')

# Compliant: does not trigger
pattern2 = re.compile(r'[A-Z]')
