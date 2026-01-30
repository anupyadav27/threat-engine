# Test script to trigger assignments_of_lambdas_to_variables_should_be_replaced_by_function_definitions

def test_lambda_assignment():
    # Noncompliant: Lambda assigned to variable
    x = lambda y: y + 1
    result = x(2)
    print(result)

# Compliant: Function definition
# def add_one(y):
#     return y + 1
# y = add_one(2)
# print(y)

if __name__ == "__main__":
    test_lambda_assignment()
