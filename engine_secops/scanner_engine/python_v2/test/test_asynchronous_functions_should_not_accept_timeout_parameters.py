"""
Test for asynchronous_functions_should_not_accept_timeout_parameters rule
This test triggers the rule by defining an async function with a timeout parameter.
"""

def bad_async_timeout():
    async def my_func(timeout):
        pass

# Compliant example (should NOT trigger the rule)
def good_async_no_timeout():
    async def my_func():
        pass
