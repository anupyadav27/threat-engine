# Test script to trigger the 'generators and comprehensions should be preferred over map and lambda' rule

def test_map_usage():
    numbers = [1, 2, 3, 4]
    result = list(map(lambda x: x**2, numbers))  # Should trigger the rule
    return result

def test_lambda_usage():
    numbers = [1, 2, 3, 4]
    result = list(map(lambda x: x+1, numbers))  # Should trigger the rule
    return result

if __name__ == "__main__":
    print(test_map_usage())
    print(test_lambda_usage())
