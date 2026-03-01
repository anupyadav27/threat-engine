class ParentException(Exception):
    pass

class ChildException(ParentException):
    pass

def test_subclass_and_parent_in_same_except():
    try:
        raise ChildException()
    except (ParentException, ChildException):
        # This should trigger the rule: subclass and parent in same except
        pass

def test_separate_except_blocks():
    try:
        raise ChildException()
    except ParentException:
        pass
    except ChildException:
        pass  # This should NOT trigger the rule
