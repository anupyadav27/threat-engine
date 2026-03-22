#!/usr/bin/env python3
"""
Test file to trigger: assertions_comparing_incompatible_types_should_not_be_made

This file contains various examples of assertions that compare incompatible types,
which should be detected by the scanner as code smells.
"""

def test_incompatible_type_assertions():
    """Function with various incompatible type comparisons in assertions"""
    
    # Direct incompatible type comparisons - should trigger the rule
    assert 1 == 'a'  # int vs string
    assert 'hello' == 42  # string vs int
    assert True == 'true'  # bool vs string
    assert 3.14 == '3.14'  # float vs string
    assert [1, 2, 3] == '123'  # list vs string
    assert {'key': 'value'} == 'dict'  # dict vs string
    assert (1, 2) == '12'  # tuple vs string
    
    # More complex incompatible comparisons
    x = 100
    y = "100"
    assert x == y  # int variable vs string variable
    
    # Function return vs incompatible type
    def get_number():
        return 42
    
    assert get_number() == "42"  # function returning int vs string
    
    # List/dict operations with incompatible types
    my_list = [1, 2, 3]
    assert my_list == "123"  # list vs string
    
    my_dict = {"count": 5}
    assert my_dict == 5  # dict vs int
    
    # Boolean vs string/number comparisons
    is_valid = True
    assert is_valid == "True"  # bool vs string
    assert is_valid == 1  # This might be acceptable in Python, but still incompatible types
    
    # None vs other types
    result = None
    assert result == "None"  # None vs string
    assert result == 0  # None vs int
    
    # Complex expressions with incompatible types
    assert len("hello") == "5"  # int result vs string
    assert str(123) == 123  # string vs int (opposite direction)
    
    # Class instance vs primitive type
    class MyClass:
        def __init__(self, value):
            self.value = value
    
    obj = MyClass(42)
    assert obj == 42  # object vs int
    assert obj == "MyClass"  # object vs string


def test_more_incompatible_assertions():
    """Additional test cases for incompatible type assertions"""
    
    # Nested data structures
    nested_list = [[1, 2], [3, 4]]
    assert nested_list == "[[1, 2], [3, 4]]"  # nested list vs string
    
    # Set vs other types
    my_set = {1, 2, 3}
    assert my_set == [1, 2, 3]  # set vs list
    assert my_set == "123"  # set vs string
    
    # Range vs other types
    my_range = range(5)
    assert my_range == [0, 1, 2, 3, 4]  # range vs list
    assert my_range == "range(0, 5)"  # range vs string
    
    # Lambda function vs other types
    func = lambda x: x * 2
    assert func == "lambda function"  # function vs string
    
    # Module comparison (if imported)
    import os
    assert os == "os"  # module vs string


def test_edge_cases():
    """Edge cases for incompatible type assertions"""
    
    # Empty containers vs strings
    assert [] == ""  # empty list vs empty string
    assert {} == ""  # empty dict vs empty string
    assert set() == ""  # empty set vs empty string
    
    # Numeric types that might seem compatible but aren't
    assert 1 == 1.0  # int vs float (might be acceptable, but technically different types)
    assert 5 == complex(5, 0)  # int vs complex
    
    # String representations
    number = 42
    assert number == f"{number}"  # int vs its string representation
    
    # Type annotations won't help here, but let's include them
    def typed_function(value: int) -> str:
        return str(value)
    
    result: str = typed_function(100)
    assert result == 100  # string return vs int


if __name__ == "__main__":
    # This would cause runtime errors if executed
    print("This file is designed to trigger rule violations, not to be executed")
    print("Run the scanner on this file to detect incompatible type assertion issues")
    
    # Uncomment below to see actual runtime behavior (will cause AssertionError)
    # test_incompatible_type_assertions()