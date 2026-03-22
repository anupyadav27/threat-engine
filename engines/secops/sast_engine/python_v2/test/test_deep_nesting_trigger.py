# This should trigger the rule: 4 levels of nested control flow statements
if a:
    for b in range(1):
        while c:
            try:
                print("Too deeply nested!")

# These should NOT trigger the rule
if a:
    for b in range(1):
        while c:
            print("3 levels nested, allowed")
