# This script intentionally violates the rule:
# "A field should not duplicate the name of its containing class"

class Employee:
    def __init__(self):
        self.Employee = "John Doe"  # ❌ Same name as class — should trigger the rule
