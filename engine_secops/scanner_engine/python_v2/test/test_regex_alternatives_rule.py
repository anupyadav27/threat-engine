# Test script to trigger the 'regex_alternatives_should_not_be_redundant' rule

import re

def test_redundant_regex():
    # Noncompliant: should trigger the rule - redundant 'b'
    pattern1 = re.compile(r'a|b|b')
    
    # Noncompliant: should trigger the rule - redundant 'foo'
    pattern2 = re.compile(r'foo|bar|foo')

    # Noncompliant: should trigger the rule - redundant 'xyz'
    pattern3 = re.compile(r'abc|xyz|def|xyz')

# Compliant examples (should NOT trigger the rule)
def test_valid_regex():
    # Compliant: no redundant alternatives
    pattern1 = re.compile(r'a|b|c')
    
    # Compliant: unique alternatives
    pattern2 = re.compile(r'foo|bar|baz')

    # Compliant: similar but not identical alternatives
    pattern3 = re.compile(r'abc|abcd|ab')