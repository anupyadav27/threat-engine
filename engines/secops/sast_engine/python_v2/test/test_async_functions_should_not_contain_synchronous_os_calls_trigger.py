# Test script to trigger async_functions_should_not_contain_synchronous_os_calls

import os

async def my_func():
    # Noncompliant: synchronous OS call in async function
    os.system('echo hello')
    os.mkdir('testdir')
    os.chdir('testdir')

if __name__ == "__main__":
    import asyncio
    asyncio.run(my_func())
