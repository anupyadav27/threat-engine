# Noncompliant: should trigger the rule
from typing import List, Dict, Set, Tuple, Optional

def func1(arg: List):
    pass

def func2(arg: Dict):
    pass

def func3(arg: Set):
    pass

def func4(arg: Tuple):
    pass

def func5(arg: Optional):
    pass

# Compliant: should NOT trigger the rule
def func6(arg: List[str]):
    pass

def func7(arg: Dict[str, int]):
    pass

def func8(arg: Set[int]):
    pass

def func9(arg: Tuple[int, int]):
    pass

def func10(arg: Optional[str]):
    pass
import sys
sys.path.insert(0, '../')
from python_scanner import scan_file_for_rules

def test_type_hints_of_generic_types_should_specify_their_type_parameters():
    # Example of missing type parameters in generic type hints
    code = '''
from typing import List, Dict, Set, Tuple, Optional

def func1(arg: List):
    pass

def func2(arg: Dict):
    pass

def func3(arg: Set):
    pass

def func4(arg: Tuple):
    pass

def func5(arg: Optional):
    pass
'''
    # Save code to a temporary file
    test_file = 'temp_type_hint_generic.py'
    with open(test_file, 'w') as f:
        f.write(code)
    # Scan the file for the rule
    results = scan_file_for_rules(test_file, rules=["type_hints_of_generic_types_should_specify_their_type_parameters"])
    # Clean up
    import os
    os.remove(test_file)
    # Assert the rule is triggered
    assert any(r['rule_id'] == 'type_hints_of_generic_types_should_specify_their_type_parameters' for r in results), "Rule not triggered!"
    print("Test passed: type_hints_of_generic_types_should_specify_their_type_parameters triggered.")

if __name__ == "__main__":
    test_type_hints_of_generic_types_should_specify_their_type_parameters()
