import sys
sys.path.insert(0, '../')
from python_scanner import scan_file_for_rules

def test_raised_exceptions_must_derive_from_baseexception():
    # Example of a custom exception not derived from BaseException
    code = '''
# Should trigger - direct inheritance from Exception
class CustomException(Exception):
    """Custom exception class"""
    pass

# Should trigger - inheritance through another exception
class DatabaseException(Exception):
    pass

class QueryException(DatabaseException):
    pass

# Should NOT trigger - proper inheritance from BaseException
class ProperException(BaseException):
    pass

def raise_error():
    raise CustomException("Error")
'''
    # Save code to a temporary file
    test_file = 'temp_custom_exception.py'
    with open(test_file, 'w') as f:
        f.write(code)
    # Scan the file for the rule
    results = scan_file_for_rules(test_file, rules=["raised_exceptions_must_derive_from_BaseException"])
    # Clean up
    import os
    os.remove(test_file)
    # Assert the rule is triggered
    assert any(r['rule_id'] == 'raised_exceptions_must_derive_from_BaseException' for r in results), "Rule not triggered!"
    print("Test passed: raised_exceptions_must_derive_from_BaseException triggered.")

if __name__ == "__main__":
    test_raised_exceptions_must_derive_from_baseexception()
