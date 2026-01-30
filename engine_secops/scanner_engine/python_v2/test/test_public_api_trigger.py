# This should trigger the rule: public API class and method
class MyPublicAPI:
    def sensitive_data(self):
        return self.secret_value

# These should NOT trigger the rule
class MyAPI:
    __slots__ = ("sensitive_data")
    def __init__(self):
        self.sensitive_data = None
    def get_sensitive_data(self):
        if self.authenticated():
            return self.sensitive_data
