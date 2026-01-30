class MinimalUnreadPrivateAttr:
    _never_read = 42  # Should trigger: unread private attribute
class TestUnreadPrivateAttributes:
    def test_unread_private_attr(self):
        class MyClass:
            def __init__(self):
                self._unused_attr = 123  # Should trigger: unread private attribute
            def use_attr(self):
                pass

    def test_read_private_attr(self):
        class MyClass:
            def __init__(self):
                self._used_attr = 456
            def use_attr(self):
                return self._used_attr  # Should NOT trigger: attribute is read

    def test_public_attr(self):
        class MyClass:
            def __init__(self):
                self.public_attr = 789  # Should NOT trigger: public attribute
            def use_attr(self):
                return self.public_attr

    def test_multiple_private_attrs(self):
        class MyClass:
            def __init__(self):
                self._read_attr = 1
                self._unread_attr = 2  # Should trigger: unread private attribute
            def use_attr(self):
                return self._read_attr

    def test_private_attr_used_in_method(self):
        class MyClass:
            def __init__(self):
                self._used_in_method = 3
            def get_value(self):
                return self._used_in_method  # Should NOT trigger
# Test script to trigger unread_private_attributes_should_be_removed rule

class MyClass:
    _unused_attr = 42  # This private attribute is never read

    def foo(self):
        pass

if __name__ == "__main__":
    obj = MyClass()
    obj.foo()
