# Noncompliant: triggers character_classes_in_regular_expressions_should_not_contain_the_same_character_twice
import re
pattern1 = re.compile(r'[Aa]')  # 'A' appears twice in the character class

# Compliant: does not trigger
pattern2 = re.compile(r'[AB]')  # Unique characters in the character class
