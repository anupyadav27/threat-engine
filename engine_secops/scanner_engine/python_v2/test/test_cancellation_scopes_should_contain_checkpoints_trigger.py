async def some_task():
    pass

async def main():
    async with cancel_token:
        for i in range(10):
            await some_task()
            cancel_token.cancel()
