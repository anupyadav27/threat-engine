# Test script to trigger async_functions_should_not_contain_synchronous_subprocess_calls

import subprocess

async def a():
    # Noncompliant: synchronous subprocess call in async function
    subprocess.run(['echo', 'hello'])
    subprocess.call(['ls', '-l'])
    proc = subprocess.Popen(['sleep', '1'])
    proc.wait()

if __name__ == "__main__":
    import asyncio
    asyncio.run(a())
