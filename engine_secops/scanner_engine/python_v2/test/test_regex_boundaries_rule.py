# Test script to trigger the 'regex_boundaries_should_not_be_used_in_a_way_that_can_never_be_matched' rule

import re

def test_impossible_boundaries():
    # Noncompliant: should trigger the rule
    
    # Adjacent word boundaries that can never match
    pattern1 = re.compile(r'\b\bword')
    
    # Multiple start anchors that can never match
    pattern2 = re.compile(r'^start^text')
    
    # Multiple end anchors that can never match
    pattern3 = re.compile(r'text$end$')
    
    # Adjacent negative lookbehinds that can never match
    pattern4 = re.compile(r'(?<!a)(?<!b)text')
    
    # Adjacent negative lookaheads that can never match
    pattern5 = re.compile(r'text(?!a)(?!b)')

# Compliant examples (should NOT trigger the rule)
def test_valid_boundaries():
    # Compliant: single word boundary
    pattern1 = re.compile(r'\bword\b')
    
    # Compliant: single start anchor
    pattern2 = re.compile(r'^start')
    
    # Compliant: single end anchor
    pattern3 = re.compile(r'end$')
    
    # Compliant: single negative lookbehind
    pattern4 = re.compile(r'(?<!a)text')
    
    # Compliant: single negative lookahead
    pattern5 = re.compile(r'text(?!a)')
    
    # Compliant: mixed boundaries used correctly
    pattern6 = re.compile(r'^\bword\b$')