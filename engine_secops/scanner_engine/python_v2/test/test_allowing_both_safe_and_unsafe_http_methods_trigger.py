# Test to trigger 'allowing_both_safe_and_unsafe_http_methods_is_securitysensitive'

class MyAPI:
    def get_data(self):
        pass  # Safe method
    def post_data(self):
        pass  # Unsafe method
    def put_data(self):
        pass  # Unsafe method

class SafeAPI:
    def get_data(self):
        pass  # Only safe method
