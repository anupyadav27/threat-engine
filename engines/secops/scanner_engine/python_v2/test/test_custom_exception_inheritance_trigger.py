# Test script to trigger the custom_exception_classes_should_inherit_from_exception_or_one_of_its_subclasses rule

# This should trigger the rule (inherits from object)
class BadCustomException(object):
    pass

# This should NOT trigger the rule (inherits from Exception)
class GoodCustomException(Exception):
    pass

# This should NOT trigger the rule (inherits from a subclass of Exception)
class AnotherGoodCustomException(ValueError):
    pass
