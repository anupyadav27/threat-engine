"""
Test for async_with_should_be_used_for_asynchronous_resource_management rule
This test triggers the rule by using a synchronous 'with' inside an async function.
"""

def bad_async_with_usage():
    async def func():
        with open("file.txt", "r") as f:
            data = await f.read()

# Compliant example (should NOT trigger the rule)
def good_async_with_usage():
    async def func():
        async with open("file.txt", "r") as f:
            data = await f.read()
