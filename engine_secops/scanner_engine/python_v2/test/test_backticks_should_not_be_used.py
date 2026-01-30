# Test script to trigger backticks_should_not_be_used rule only

# Noncompliant: using backticks for variable name (simulated, as Python does not allow this syntax)
# The following line is not valid Python, but is used to simulate the AST node for testing purposes:
# x = `var`

# To trigger the rule in a real Python AST, you may need to simulate or mock the AST node, or adjust the scanner to recognize this pattern in comments or strings.

# For demonstration, we use a string that matches the forbidden pattern:
var_name = '`var`'  # This should trigger the rule if the scanner checks string assignments
