# Test for async_functions_should_use_async_features
async def nc_func():
    print('Hello')

# Compliant example (should NOT trigger the rule)
async def c_func():
    await some_async_func()
    print('Hello')

# Compliant example (should NOT trigger the rule)
async def c_func2():
    async with some_async_contextmanager():
        print('Hello')
