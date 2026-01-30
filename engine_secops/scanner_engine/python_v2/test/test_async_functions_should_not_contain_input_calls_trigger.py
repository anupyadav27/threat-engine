# Test script to trigger async_functions_should_not_contain_input_calls

import asyncio

async def example():
    # Noncompliant: input call in async function
    x = input('Prompt: ')
    return x

if __name__ == "__main__":
    import sys
    if sys.version_info >= (3, 7):
        asyncio.run(example())
    else:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(example())
