# Test to trigger 'all_except_blocks_should_be_able_to_catch_exceptions'

def foo():
    print('Hello')  # Noncompliant: no exception handling

def bar():
    try:
        print('Handled')
    except Exception:
        print('Caught')  # Compliant: has except block

import contextlib
@contextlib.contextmanager
def baz():
    yield  # Compliant: decorated with @contextmanager
