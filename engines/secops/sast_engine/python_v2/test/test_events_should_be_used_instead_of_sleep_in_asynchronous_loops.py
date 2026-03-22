import asyncio

async def example():
    await asyncio.sleep(5)
    print("Slept for 5 seconds")

# Compliant example for reference (not triggered):
# async def example_event():
#     event = asyncio.Event()
#     await asyncio.wait_for(event.wait(), timeout=5)
#     print("Waited for event")
#     event.set()
