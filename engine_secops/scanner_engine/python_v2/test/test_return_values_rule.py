"""Test cases for the rule 'Return values from functions without side effects should not be ignored'."""

class ReturnValueTest:
    """Test class with various method types for testing return value rules."""

    def __init__(self):
        """Initialize test class instance.
        
        Should NOT trigger the rule since constructors are excluded.
        """
        self._value = None

    def _log(self, message):
        """Internal logging helper.
        
        Args:
            message: Message to log
        """
        # Using print for demonstration, would use logger in real code
        print(message)  

    @property 
    def value(self):
        """Property getter for value."""
        return self._value

    @value.setter 
    def value(self, val):
        """Property setter for value.
        
        Should NOT trigger the rule since property setters are designed to modify state.
        
        Args:
            val: Value to set
        """
        self._value = val
        self._log(f"Value set to {val}")

    def void_method(self):
        """Method without return value.
        
        Should trigger the rule since it lacks a return value.
        """
        self._log("No return value here")

def function_without_return():
    """Function that demonstrates lack of return value.
    
    Should trigger the rule since there is no return statement.
    """
    x = 5  
    print("This function has no return value")

def function_with_empty_return():
    """Function that demonstrates empty return statement.
    
    Should trigger the rule since the return statement has no value.
    """
    print("This function has empty return")
    return

def function_with_side_effects():
    """Function that demonstrates side effects.
    
    Should NOT trigger the rule since it modifies global state.
    """
    # Using globals is generally bad practice but used here to demonstrate side effects
    global some_var  
    some_var = 42

def function_with_proper_return():
    """Function that demonstrates proper return value.
    
    Should NOT trigger the rule since it properly returns a value.
    """
    x = 5
    return x

def test_functions_without_return():
    """Test functions without return values.
    
    Tests both proper and improper use of function return values.
    """
    # Test function that lacks return value
    try:
        function_without_return()
    except Exception as e:
        # We expect this to complete without error, even though it lacks return
        assert False, f"Should not raise: {e}"
    
    # Test function with empty return
    try:
        function_with_empty_return()
    except Exception as e:
        assert False, f"Should not raise: {e}"
    
    # Test function with side effects (should be ok)
    try:
        function_with_side_effects()
        assert some_var == 42  # Verify side effect
    except Exception as e:
        assert False, f"Should not raise: {e}"
    
    # Test function with proper return
    try:
        x = function_with_proper_return()
        assert x == 5
    except Exception as e:
        assert False, f"Should not raise: {e}"
        
def test_return_value_test_class():
    """Test ReturnValueTest class functionality."""
    test = ReturnValueTest()
    
    # Test property getter/setter
    try:
        test.value = 42
        assert test.value == 42
    except Exception as e:
        assert False, f"Property access failed: {e}"
        
    # Test void method
    try:
        test.void_method()
    except Exception as e:
        assert False, f"Void method failed: {e}"