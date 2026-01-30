# Noncompliant: triggers character_classes_should_be_preferred_over_reluctant_quantifiers_in_regular_expressions
import re
pattern1 = re.compile(r'.*?example')  # Uses reluctant quantifier '*?'
pattern2 = re.compile(r'.+?example')  # Uses reluctant quantifier '+?'
pattern3 = re.compile(r'(?!example).*')  # Uses negative lookahead '(?!)'
pattern4 = re.compile(r'.??example')  # Uses reluctant quantifier '??'

# Compliant: does not trigger
pattern5 = re.compile(r'[^example]*.*')  # Uses character class
