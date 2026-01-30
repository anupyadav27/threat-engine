# Test script to trigger only the boolean_expressions_of_exceptions_should_not_be_used_in_except_statements rule

def test_boolean_expression_in_except():
    try:
        x = 1 / 0
    except (Exception and True):  # Should trigger: boolean expression in except statement
        pass

def test_explicit_exception():
    try:
        x = 1 / 0
    except Exception:  # Should NOT trigger
        pass

if __name__ == "__main__":
    test_boolean_expression_in_except()
    test_explicit_exception()
