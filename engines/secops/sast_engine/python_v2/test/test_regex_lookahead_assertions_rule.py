# Test script to trigger the 'regex_lookahead_assertions_should_not_be_contradictory' rule

import re

def test_contradictory_lookaheads():
    # Noncompliant: should trigger the rule
    
    # Direct contradiction - can't both look ahead for 'x' and not 'x'
    pattern1 = re.compile(r'(?=x)(?!x)z')
    
    # Contradiction with groups
    pattern2 = re.compile(r'(?=(a|b))(?!a)z')
    
    # Reverse order contradiction
    pattern3 = re.compile(r'(?!x)(?=x)z')
    
    # Complex contradiction with multiple characters
    pattern4 = re.compile(r'(?=(foo|bar))(?!foo)z')

# Compliant examples (should NOT trigger the rule)
def test_valid_lookaheads():
    # Compliant: lookaheads for different things
    pattern1 = re.compile(r'(?=x)(?!y)z')
    
    # Compliant: multiple positive lookaheads
    pattern2 = re.compile(r'(?=.*[A-Z])(?=.*[a-z])z')
    
    # Compliant: multiple negative lookaheads
    pattern3 = re.compile(r'(?!abc)(?!def)z')
    
    # Compliant: complex but non-contradictory pattern
    pattern4 = re.compile(r'(?=.*[0-9])(?!.*[!@#$])z')
    
    # Compliant: positive and negative lookaheads for different patterns
    pattern5 = re.compile(r'(?=\w+)(?![0-9]+$)z')