"""
Tests for retry handler
"""
import pytest
import asyncio
from common.retry_handler import retry_with_backoff


# Test async function
@retry_with_backoff(max_retries=3, initial_delay=0.1, exceptions=(ValueError,))
async def async_function_that_fails_then_succeeds(call_count):
    """Function that fails first 2 times, then succeeds"""
    call_count[0] += 1
    if call_count[0] < 3:
        raise ValueError(f"Attempt {call_count[0]} failed")
    return "success"


@retry_with_backoff(max_retries=2, initial_delay=0.1, exceptions=(ValueError,))
async def async_function_that_always_fails():
    """Function that always fails"""
    raise ValueError("Always fails")


# Test sync function
@retry_with_backoff(max_retries=3, initial_delay=0.1, exceptions=(ValueError,))
def sync_function_that_fails_then_succeeds(call_count):
    """Function that fails first 2 times, then succeeds"""
    call_count[0] += 1
    if call_count[0] < 3:
        raise ValueError(f"Attempt {call_count[0]} failed")
    return "success"


@retry_with_backoff(max_retries=2, initial_delay=0.1, exceptions=(ValueError,))
def sync_function_that_always_fails():
    """Function that always fails"""
    raise ValueError("Always fails")


@pytest.mark.asyncio
async def test_async_retry_success():
    """Test async retry that eventually succeeds"""
    call_count = [0]
    result = await async_function_that_fails_then_succeeds(call_count)
    assert result == "success"
    assert call_count[0] == 3  # Should have been called 3 times


@pytest.mark.asyncio
async def test_async_retry_failure():
    """Test async retry that eventually fails"""
    with pytest.raises(ValueError, match="Always fails"):
        await async_function_that_always_fails()


def test_sync_retry_success():
    """Test sync retry that eventually succeeds"""
    call_count = [0]
    result = sync_function_that_fails_then_succeeds(call_count)
    assert result == "success"
    assert call_count[0] == 3  # Should have been called 3 times


def test_sync_retry_failure():
    """Test sync retry that eventually fails"""
    with pytest.raises(ValueError, match="Always fails"):
        sync_function_that_always_fails()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
