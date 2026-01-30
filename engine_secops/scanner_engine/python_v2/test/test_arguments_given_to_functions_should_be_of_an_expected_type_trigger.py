# Minimal test to trigger: arguments_given_to_functions_should_be_of_an_expected_type

def f(x: str):
    pass

# Noncompliant: argument is an integer when function expects a string
f(123)

# Keep the file minimal to avoid triggering unrelated rules
