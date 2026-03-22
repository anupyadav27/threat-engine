# Noncompliant: yield and return outside functions
x = yield 42
return 99

def good_func():
    yield 1
    return 2
