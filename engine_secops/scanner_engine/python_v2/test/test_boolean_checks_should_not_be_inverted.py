# Noncompliant: Should trigger 'boolean_checks_should_not_be_inverted'
def compare(x, y):
    if not x > y:
        print('x is not greater than y')

# Compliant: Should not trigger
# def compare(x, y):
#     if x <= y:
#         print('x is less than or equal to y')

if __name__ == "__main__":
    compare(1, 2)
