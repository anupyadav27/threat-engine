# Test script to trigger unused_function_parameters_should_be_removed rule

def foo(x, y):
    return x  # 'y' is never used
