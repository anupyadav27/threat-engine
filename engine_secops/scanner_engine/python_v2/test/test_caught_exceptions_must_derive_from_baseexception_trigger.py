# Noncompliant: triggers caught_exceptions_must_derive_from_baseexception
class MyCustomException(Exception):
    pass

def test_func():
    try:
        raise MyCustomException()
    except Exception:
        pass

# Compliant: does not trigger
class MyOtherException(BaseException):
    pass

def test_func2():
    try:
        raise MyOtherException()
    except BaseException:
        pass
