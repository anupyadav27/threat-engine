# Test script to trigger unused_classprivate_methods_should_be_removed rule

class MyClass:
    def _unused_method(self):
        pass

    def foo(self):
        print("Hello, world!")
