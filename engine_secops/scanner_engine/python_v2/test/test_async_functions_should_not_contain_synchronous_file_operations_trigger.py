# Test script to trigger async_functions_should_not_contain_synchronous_file_operations

async def read_file(file_path):
    # Noncompliant: synchronous file operation in async function
    with open(file_path, 'r') as f:
        return f.read()

if __name__ == "__main__":
    import asyncio
    import tempfile
    # Create a temp file for demonstration
    with tempfile.NamedTemporaryFile(delete=False, mode='w') as tmp:
        tmp.write('test content')
        temp_path = tmp.name
    # Run the async function
    asyncio.run(read_file(temp_path))
