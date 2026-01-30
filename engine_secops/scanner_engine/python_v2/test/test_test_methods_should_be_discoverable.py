import sys
sys.path.insert(0, '../')
from python_scanner import scan_file_for_rules

def test_test_methods_should_be_discoverable():
    # Example of a non-discoverable test method
    code = '''
def _test_hidden():
    pass

def __test_private():
    pass

def _TestSomething():
    pass
'''
    # Save code to a temporary file
    test_file = 'temp_test_discoverable.py'
    with open(test_file, 'w') as f:
        f.write(code)
    # Scan the file for the rule
    results = scan_file_for_rules(test_file, rules=["test_methods_should_be_discoverable"])
    # Clean up
    import os
    os.remove(test_file)
    # Assert the rule is triggered
    assert any(r['rule_id'] == 'test_methods_should_be_discoverable' for r in results), "Rule not triggered!"
    print("Test passed: test_methods_should_be_discoverable triggered.")

if __name__ == "__main__":
    test_test_methods_should_be_discoverable()
