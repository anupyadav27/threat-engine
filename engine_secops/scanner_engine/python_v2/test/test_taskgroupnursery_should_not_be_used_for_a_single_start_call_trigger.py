"""Test for taskgroupnursery_should_not_be_used_for_a_single_start_call rule only."""

async def my_function():
    async with TaskGroup() as tg:
        tg.start_soon(my_task)
