import sys
sys.path.insert(0, '../')
from python_scanner import scan_file_for_rules

def test_tensorflowfunction_should_not_be_recursive():
    # Example of a recursive TensorFlow function
    code = '''
import tensorflow as tf

@tf.function
def recursive_function(x):
    if x > 1:
        return tf.add(recursive_function(x - 1), tf.constant(1))
    return tf.constant(x)
'''
    # Save code to a temporary file
    test_file = 'temp_recursive_tf.py'
    with open(test_file, 'w') as f:
        f.write(code)
    # Scan the file for the rule
    results = scan_file_for_rules(test_file, rules=["tensorflowfunction_should_not_be_recursive"])
    # Clean up
    import os
    os.remove(test_file)
    # Assert the rule is triggered
    assert any(r['rule_id'] == 'tensorflowfunction_should_not_be_recursive' for r in results), "Rule not triggered!"
    print("Test passed: tensorflowfunction_should_not_be_recursive triggered.")

if __name__ == "__main__":
    test_tensorflowfunction_should_not_be_recursive()
