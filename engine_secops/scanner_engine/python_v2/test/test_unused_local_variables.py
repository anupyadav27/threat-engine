# Test script to trigger unused_local_variables_should_be_removed rule

def bar():
    unused_var = 123  # This variable is never used
    print("Hello")
