# Test script to trigger unused_scopelimited_definitions_should_be_removed rule

def foo():
    _UNUSED_VAR = 42  # Unused scope-limited definition
    pass
