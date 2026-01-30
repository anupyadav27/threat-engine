"""
Tests for circuit breaker
"""
import pytest
import time
from engine_common.circuit_breaker import CircuitBreaker, CircuitState, get_circuit_breaker


def test_circuit_breaker_closed_state():
    """Test circuit breaker in closed state (normal operation)"""
    breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=1.0)
    
    def success_function():
        return "success"
    
    result = breaker.call(success_function)
    assert result == "success"
    assert breaker.state == CircuitState.CLOSED
    assert breaker.failure_count == 0


def test_circuit_breaker_opens_after_failures():
    """Test circuit breaker opens after threshold failures"""
    breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=1.0)
    
    def failing_function():
        raise ValueError("Test error")
    
    # Fail 3 times
    for i in range(3):
        with pytest.raises(ValueError):
            breaker.call(failing_function)
    
    # Circuit should be open now
    assert breaker.state == CircuitState.OPEN
    assert breaker.failure_count == 3
    
    # Next call should be rejected immediately
    def success_function():
        return "success"
    
    with pytest.raises(Exception, match="Circuit breaker is OPEN"):
        breaker.call(success_function)


def test_circuit_breaker_half_open_recovery():
    """Test circuit breaker recovery through half-open state"""
    breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=0.5)
    
    def failing_function():
        raise ValueError("Test error")
    
    # Open the circuit
    for i in range(2):
        with pytest.raises(ValueError):
            breaker.call(failing_function)
    
    assert breaker.state == CircuitState.OPEN
    
    # Wait for recovery timeout
    time.sleep(0.6)
    
    # Next call should transition to half-open
    def success_function():
        return "success"
    
    # This should work and close the circuit
    result = breaker.call(success_function)
    assert result == "success"
    assert breaker.state == CircuitState.CLOSED
    assert breaker.failure_count == 0


@pytest.mark.asyncio
async def test_circuit_breaker_async():
    """Test circuit breaker with async functions"""
    breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=0.5)
    
    async def async_success():
        return "success"
    
    async def async_fail():
        raise ValueError("Test error")
    
    # Should work normally
    result = await breaker.call_async(async_success)
    assert result == "success"
    
    # Fail to open circuit
    for i in range(2):
        with pytest.raises(ValueError):
            await breaker.call_async(async_fail)
    
    assert breaker.state == CircuitState.OPEN


def test_get_circuit_breaker():
    """Test getting circuit breaker instances"""
    breaker1 = get_circuit_breaker("service1")
    breaker2 = get_circuit_breaker("service1")
    breaker3 = get_circuit_breaker("service2")
    
    # Same service should return same instance
    assert breaker1 is breaker2
    
    # Different service should return different instance
    assert breaker1 is not breaker3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
