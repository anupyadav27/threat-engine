# Test script to trigger the 'regex_patterns_following_a_possessive_quantifier_should_not_always_fail' rule

import re

def test_problematic_quantifiers():
    # Noncompliant: should trigger the rule
    
    # Possessive star quantifier at the end
    pattern1 = re.compile(r'abc*+')
    
    # Possessive plus quantifier at the end
    pattern2 = re.compile(r'\w++')
    
    # Lazy quantifier at the end
    pattern3 = re.compile(r'(.*?)+?')
    
    # Possessive range quantifier at the end
    pattern4 = re.compile(r'[a-z]{2,4}+')
    
    # Lazy fixed quantifier at the end
    pattern5 = re.compile(r'\d{3}?')

# Compliant examples (should NOT trigger the rule)
def test_valid_quantifiers():
    # Compliant: standard quantifier at the end
    pattern1 = re.compile(r'abc*')
    
    # Compliant: possessive quantifier not at the end
    pattern2 = re.compile(r'\w++\d')
    
    # Compliant: normal lazy quantifier not at the end
    pattern3 = re.compile(r'(.*?)xyz')
    
    # Compliant: standard range quantifier
    pattern4 = re.compile(r'[a-z]{2,4}')
    
    # Compliant: quantifier with following pattern
    pattern5 = re.compile(r'\d{3}?\w+')