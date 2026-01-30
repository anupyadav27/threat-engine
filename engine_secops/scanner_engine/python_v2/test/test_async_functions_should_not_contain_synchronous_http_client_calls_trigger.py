# Test script to trigger async_functions_should_not_contain_synchronous_http_client_calls

import requests

async def my_async_function():
    # Noncompliant: synchronous HTTP client call in async function
    response = requests.get('http://example.com')
    return response

if __name__ == "__main__":
    import asyncio
    asyncio.run(my_async_function())
