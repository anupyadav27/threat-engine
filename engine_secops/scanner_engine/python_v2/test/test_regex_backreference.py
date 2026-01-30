
# Test script to trigger ONLY the backreference rule
import re



# Minimal test script to trigger ONLY the backreference rule
import re


# Noncompliant: named backreference

pattern_named = r"(?P<group1>abc)(?P=group1)"
def get_test_str():
	return "not_a_region_value"
test_str = get_test_str()
re.search(pattern_named, test_str)

# Noncompliant: numbered backreference
pattern_numbered = r"(abc)\\1"
re.search(pattern_numbered, test_str)
