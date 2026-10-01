"""
Comprehensive test suite for circuit_breaker module
Tests retry logic, circuit breaker patterns, exponential backoff, and resilience
"""

import pytest
import asyncio
import time
from unittest.mock import Mock, AsyncMock, patch
from core.resilience.circuit_breaker import (
    RetryConfig,
    CircuitBreakerState,
    CircuitBreakerConfig,
    calculate_delay,
    is_retryable_error,
    with_retry,
    CircuitBreaker,
    with_retry_and_circuit_breaker,
    with_timeout,
    vlm_circuit_breaker,
    db_circuit_breaker,
)


class TestRetryConfigDefaults:
    """Test RetryConfig default values"""

    def test_default_max_attempts(self):
        """Test default max attempts"""
        config = RetryConfig()
        assert config.max_attempts == 3

    def test_default_initial_delay(self):
        """Test default initial delay"""
        config = RetryConfig()
        assert config.initial_delay_ms == 1000

    def test_default_max_delay(self):
        """Test default max delay"""
        config = RetryConfig()
        assert config.max_delay_ms == 30000

    def test_default_backoff_multiplier(self):
        """Test default backoff multiplier"""
        config = RetryConfig()
        assert config.backoff_multiplier == 2.0

    def test_default_retryable_errors(self):
        """Test default retryable error list"""
        config = RetryConfig()
        assert 'timeout' in config.retryable_errors
        assert 'econnreset' in config.retryable_errors
        assert len(config.retryable_errors) == 10


class TestExponentialBackoff:
    """Test exponential backoff calculation"""

    def test_first_attempt_delay(self):
        """Test delay for first attempt"""
        config = RetryConfig(initial_delay_ms=1000, max_delay_ms=30000, backoff_multiplier=2.0)
        delay = calculate_delay(1, config)
        # First attempt: 1000ms with jitter (±25%)
        assert 750 <= delay <= 1250

    def test_exponential_growth(self):
        """Test that delay grows exponentially"""
        config = RetryConfig(initial_delay_ms=1000, max_delay_ms=30000, backoff_multiplier=2.0)

        delay1 = calculate_delay(1, config)
        delay2 = calculate_delay(2, config)
        delay3 = calculate_delay(3, config)

        # Each attempt should be roughly 2x the previous (within jitter)
        assert delay2 > delay1
        assert delay3 > delay2

    def test_max_delay_cap(self):
        """Test that delay is capped at max_delay_ms"""
        config = RetryConfig(initial_delay_ms=1000, max_delay_ms=5000, backoff_multiplier=2.0)

        # Many attempts should not exceed max
        for attempt in range(1, 10):
            delay = calculate_delay(attempt, config)
            assert delay <= 5000 * 1.25  # Allow for jitter

    def test_jitter_randomness(self):
        """Test that jitter varies (not deterministic)"""
        config = RetryConfig(initial_delay_ms=1000, max_delay_ms=30000, backoff_multiplier=2.0)

        delays = [calculate_delay(1, config) for _ in range(10)]
        # With jitter, not all delays should be identical
        assert len(set(delays)) > 1  # At least some variation

    def test_jitter_range(self):
        """Test that jitter is within ±25%"""
        config = RetryConfig(initial_delay_ms=1000)
        base = config.initial_delay_ms

        delays = [calculate_delay(1, config) for _ in range(100)]
        min_delay = min(delays)
        max_delay = max(delays)

        # Verify jitter is approximately ±25%
        assert min_delay >= base * 0.75 - 1  # Allow 1ms rounding
        assert max_delay <= base * 1.25 + 1


class TestRetryableErrorDetection:
    """Test retryable error detection"""

    def test_timeout_error_retryable(self):
        """Test that timeout errors are retryable"""
        config = RetryConfig()
        error = TimeoutError("Operation timed out")
        assert is_retryable_error(error, config) is True

    def test_connection_reset_retryable(self):
        """Test that connection reset errors are retryable"""
        config = RetryConfig()
        error = ConnectionError("ECONNRESET")
        assert is_retryable_error(error, config) is True

    def test_not_found_retryable(self):
        """Test that ENOTFOUND errors are retryable"""
        config = RetryConfig()
        error = ConnectionError("ENOTFOUND")
        assert is_retryable_error(error, config) is True

    def test_rate_limit_retryable(self):
        """Test that rate limit errors are retryable"""
        config = RetryConfig()
        error = Exception("rate limit exceeded")
        assert is_retryable_error(error, config) is True

    def test_temporarily_unavailable_retryable(self):
        """Test that 'temporarily unavailable' is retryable"""
        config = RetryConfig()
        error = Exception("Service temporarily unavailable")
        assert is_retryable_error(error, config) is True

    def test_value_error_not_retryable(self):
        """Test that ValueError is not retryable"""
        config = RetryConfig()
        error = ValueError("Invalid input")
        assert is_retryable_error(error, config) is False

    def test_custom_retryable_errors(self):
        """Test custom retryable error list"""
        config = RetryConfig(retryable_errors=['custom_error'])
        error = Exception("custom_error occurred")
        assert is_retryable_error(error, config) is True

    def test_case_insensitive_matching(self):
        """Test that error matching is case-insensitive"""
        config = RetryConfig(retryable_errors=['TIMEOUT'])
        error = Exception("timeout")
        assert is_retryable_error(error, config) is True


class TestWithRetryBasics:
    """Test basic retry functionality"""

    @pytest.mark.asyncio
    async def test_successful_first_attempt(self):
        """Test that successful call returns immediately"""
        fn = AsyncMock(return_value="success")

        result = await with_retry(fn)

        assert result == "success"
        assert fn.call_count == 1

    @pytest.mark.asyncio
    async def test_retry_on_transient_failure(self):
        """Test retry on transient failure"""
        fn = AsyncMock()
        fn.side_effect = [
            TimeoutError("timeout"),
            "success"
        ]

        result = await with_retry(fn, RetryConfig(max_attempts=3))

        assert result == "success"
        assert fn.call_count == 2

    @pytest.mark.asyncio
    async def test_all_attempts_exhausted(self):
        """Test failure after all attempts exhausted"""
        fn = AsyncMock(side_effect=TimeoutError("timeout"))
        config = RetryConfig(max_attempts=2, initial_delay_ms=10)

        with pytest.raises(TimeoutError):
            await with_retry(fn, config)

        assert fn.call_count == 2

    @pytest.mark.asyncio
    async def test_non_retryable_error_fails_immediately(self):
        """Test that non-retryable errors fail immediately"""
        fn = AsyncMock(side_effect=ValueError("invalid input"))
        config = RetryConfig(max_attempts=3, initial_delay_ms=10)

        with pytest.raises(ValueError):
            await with_retry(fn, config)

        assert fn.call_count == 1

    @pytest.mark.asyncio
    async def test_retry_callback_called(self):
        """Test that retry callback is called"""
        callback = Mock()
        fn = AsyncMock()
        fn.side_effect = [
            TimeoutError("timeout"),
            "success"
        ]

        config = RetryConfig(
            max_attempts=3,
            initial_delay_ms=10,
            on_retry=callback
        )

        await with_retry(fn, config)

        assert callback.call_count == 1
        # Check callback args: (attempt, error, delay_ms)
        args = callback.call_args[0]
        assert args[0] == 1  # First attempt
        assert isinstance(args[1], TimeoutError)
        assert isinstance(args[2], int)


class TestCircuitBreakerStates:
    """Test circuit breaker state transitions"""

    @pytest.mark.asyncio
    async def test_initial_state_closed(self):
        """Test circuit breaker starts in closed state"""
        cb = CircuitBreaker("test")
        state = cb.get_state()

        assert state.is_open is False
        assert state.failure_count == 0

    @pytest.mark.asyncio
    async def test_success_resets_failure_count(self):
        """Test that success resets failure count"""
        cb = CircuitBreaker("test")

        # Simulate some failures first
        fn_fail = AsyncMock(side_effect=Exception("error"))
        try:
            await cb.execute(fn_fail)
        except:
            pass

        # Now succeed
        fn_success = AsyncMock(return_value="ok")
        await cb.execute(fn_success)

        state = cb.get_state()
        assert state.failure_count == 0

    @pytest.mark.asyncio
    async def test_failure_increments_count(self):
        """Test that failures increment failure count"""
        config = CircuitBreakerConfig(failure_threshold=5)
        cb = CircuitBreaker("test", config)

        fn = AsyncMock(side_effect=Exception("error"))

        for i in range(3):
            try:
                await cb.execute(fn)
            except:
                pass
            state = cb.get_state()
            assert state.failure_count == i + 1

    @pytest.mark.asyncio
    async def test_open_on_threshold(self):
        """Test circuit opens when failure threshold reached"""
        config = CircuitBreakerConfig(failure_threshold=3, reset_timeout_ms=1000)
        cb = CircuitBreaker("test", config)

        fn = AsyncMock(side_effect=Exception("error"))

        for _ in range(3):
            try:
                await cb.execute(fn)
            except:
                pass

        state = cb.get_state()
        assert state.is_open is True
        assert state.failure_count == 3

    @pytest.mark.asyncio
    async def test_open_circuit_blocks_requests(self):
        """Test that open circuit blocks new requests"""
        config = CircuitBreakerConfig(failure_threshold=2, reset_timeout_ms=10000)
        cb = CircuitBreaker("test", config)

        fn = AsyncMock(side_effect=Exception("error"))

        # Open the circuit
        for _ in range(2):
            try:
                await cb.execute(fn)
            except:
                pass

        # Try to execute - should fail immediately
        fn_success = AsyncMock(return_value="ok")
        with pytest.raises(RuntimeError) as exc_info:
            await cb.execute(fn_success)

        assert "is open" in str(exc_info.value)
        assert fn_success.call_count == 0  # Should not be called

    @pytest.mark.asyncio
    async def test_half_open_allows_limited_attempts(self):
        """Test that half-open state allows limited attempts"""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            reset_timeout_ms=100,
            half_open_max_attempts=2
        )
        cb = CircuitBreaker("test", config)

        fn_fail = AsyncMock(side_effect=Exception("error"))

        # Open circuit
        for _ in range(2):
            try:
                await cb.execute(fn_fail)
            except:
                pass

        # Wait for reset timeout
        await asyncio.sleep(0.15)

        # First attempt in half-open
        try:
            await cb.execute(fn_fail)
        except:
            pass

        # Second attempt in half-open
        try:
            await cb.execute(fn_fail)
        except:
            pass

        # Third attempt should fail
        with pytest.raises(RuntimeError):
            await cb.execute(fn_fail)

    @pytest.mark.asyncio
    async def test_half_open_recovery(self):
        """Test recovery from half-open state"""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            reset_timeout_ms=100
        )
        cb = CircuitBreaker("test", config)

        fn_fail = AsyncMock(side_effect=Exception("error"))
        fn_success = AsyncMock(return_value="ok")

        # Open circuit
        for _ in range(2):
            try:
                await cb.execute(fn_fail)
            except:
                pass

        # Wait for reset
        await asyncio.sleep(0.15)

        # Successful call in half-open closes circuit
        result = await cb.execute(fn_success)

        assert result == "ok"
        state = cb.get_state()
        assert state.is_open is False
        assert state.failure_count == 0


class TestCircuitBreakerReset:
    """Test circuit breaker reset functionality"""

    @pytest.mark.asyncio
    async def test_manual_reset(self):
        """Test manual circuit breaker reset"""
        config = CircuitBreakerConfig(failure_threshold=2)
        cb = CircuitBreaker("test", config)

        fn = AsyncMock(side_effect=Exception("error"))

        # Cause failures
        for _ in range(2):
            try:
                await cb.execute(fn)
            except:
                pass

        # Reset
        cb.reset()

        state = cb.get_state()
        assert state.is_open is False
        assert state.failure_count == 0

    @pytest.mark.asyncio
    async def test_reset_half_open_attempts(self):
        """Test that reset clears half-open attempts"""
        config = CircuitBreakerConfig(failure_threshold=2, reset_timeout_ms=100)
        cb = CircuitBreaker("test", config)

        fn = AsyncMock(side_effect=Exception("error"))

        # Open circuit
        for _ in range(2):
            try:
                await cb.execute(fn)
            except:
                pass

        await asyncio.sleep(0.15)

        # Try half-open attempt
        try:
            await cb.execute(fn)
        except:
            pass

        # Reset should clear
        cb.reset()

        # Should be able to execute normally
        fn_success = AsyncMock(return_value="ok")
        result = await cb.execute(fn_success)
        assert result == "ok"


class TestRetryWithCallback:
    """Test retry callback functionality"""

    @pytest.mark.asyncio
    async def test_callback_receives_attempt_number(self):
        """Test callback receives correct attempt number"""
        callback = Mock()
        fn = AsyncMock()
        fn.side_effect = [TimeoutError("timeout"), TimeoutError("timeout"), "success"]

        config = RetryConfig(
            max_attempts=4,
            initial_delay_ms=10,
            on_retry=callback
        )

        await with_retry(fn, config)

        assert callback.call_count == 2
        # Check attempt numbers
        assert callback.call_args_list[0][0][0] == 1
        assert callback.call_args_list[1][0][0] == 2

    @pytest.mark.asyncio
    async def test_callback_receives_delay_ms(self):
        """Test callback receives correct delay"""
        callback = Mock()
        fn = AsyncMock()
        fn.side_effect = [TimeoutError("timeout"), "success"]

        config = RetryConfig(
            max_attempts=3,
            initial_delay_ms=50,
            on_retry=callback
        )

        await with_retry(fn, config)

        delay = callback.call_args[0][2]
        # First retry should have delay around 50ms (with jitter)
        assert 37 <= delay <= 63


class TestCombinedRetryCircuitBreaker:
    """Test combined retry and circuit breaker"""

    @pytest.mark.asyncio
    async def test_retry_with_circuit_breaker(self):
        """Test retry wrapped with circuit breaker"""
        cb = CircuitBreaker("test")
        fn = AsyncMock()
        fn.side_effect = [TimeoutError("timeout"), "success"]

        result = await with_retry_and_circuit_breaker(
            cb,
            fn,
            RetryConfig(max_attempts=3, initial_delay_ms=10)
        )

        assert result == "success"

    @pytest.mark.asyncio
    async def test_circuit_breaker_opens_despite_retry(self):
        """Test circuit breaker opens even with retries"""
        config_cb = CircuitBreakerConfig(failure_threshold=2, reset_timeout_ms=1000)
        cb = CircuitBreaker("test", config_cb)

        fn = AsyncMock(side_effect=Exception("error"))

        # Multiple calls should open circuit
        for _ in range(2):
            try:
                await with_retry_and_circuit_breaker(
                    cb,
                    fn,
                    RetryConfig(max_attempts=1, initial_delay_ms=10)
                )
            except:
                pass

        # Circuit should be open
        state = cb.get_state()
        assert state.is_open is True


class TestTimeout:
    """Test timeout functionality"""

    @pytest.mark.asyncio
    async def test_timeout_success(self):
        """Test function completes within timeout"""
        async def fast_fn():
            await asyncio.sleep(0.01)
            return "success"

        result = await with_timeout(fast_fn, 100)
        assert result == "success"

    @pytest.mark.asyncio
    async def test_timeout_exceeded(self):
        """Test timeout is enforced"""
        async def slow_fn():
            await asyncio.sleep(1)
            return "should not complete"

        with pytest.raises(TimeoutError):
            await with_timeout(slow_fn, 50)

    @pytest.mark.asyncio
    async def test_timeout_error_message(self):
        """Test timeout error message includes duration"""
        async def slow_fn():
            await asyncio.sleep(1)

        with pytest.raises(TimeoutError) as exc_info:
            await with_timeout(slow_fn, 50, "Custom message")

        assert "Custom message" in str(exc_info.value)
        assert "50" in str(exc_info.value)


class TestPreconfiguredBreakers:
    """Test pre-configured circuit breakers"""

    def test_vlm_circuit_breaker_config(self):
        """Test VLM circuit breaker configuration"""
        state = vlm_circuit_breaker.get_state()
        assert state.is_open is False
        assert vlm_circuit_breaker.name == 'vlm-api'
        assert vlm_circuit_breaker.config.failure_threshold == 5

    def test_db_circuit_breaker_config(self):
        """Test database circuit breaker configuration"""
        state = db_circuit_breaker.get_state()
        assert state.is_open is False
        assert db_circuit_breaker.name == 'database'
        assert db_circuit_breaker.config.failure_threshold == 3

    @pytest.mark.asyncio
    async def test_vlm_and_db_independent(self):
        """Test that VLM and DB breakers are independent"""
        # Reset both
        vlm_circuit_breaker.reset()
        db_circuit_breaker.reset()

        fn_fail = AsyncMock(side_effect=Exception("error"))

        # Open VLM breaker
        for _ in range(5):
            try:
                await vlm_circuit_breaker.execute(fn_fail)
            except:
                pass

        # DB breaker should still be closed
        state_db = db_circuit_breaker.get_state()
        assert state_db.is_open is False


class TestStressScenarios:
    """Stress test scenarios"""

    @pytest.mark.asyncio
    async def test_rapid_retries(self):
        """Test rapid retry attempts"""
        fn = AsyncMock()
        fn.side_effect = [
            TimeoutError("timeout"),
            TimeoutError("timeout"),
            "success"
        ]

        config = RetryConfig(max_attempts=5, initial_delay_ms=1)
        result = await with_retry(fn, config)

        assert result == "success"
        assert fn.call_count == 3

    @pytest.mark.asyncio
    async def test_many_circuit_breaker_failures(self):
        """Test circuit breaker with many failures"""
        config = CircuitBreakerConfig(failure_threshold=10, reset_timeout_ms=1000)
        cb = CircuitBreaker("test", config)

        fn = AsyncMock(side_effect=Exception("error"))

        for _ in range(10):
            try:
                await cb.execute(fn)
            except:
                pass

        state = cb.get_state()
        assert state.is_open is True
        assert state.failure_count == 10

    @pytest.mark.asyncio
    async def test_alternating_success_failure(self):
        """Test alternating success and failure resets on each success"""
        config = CircuitBreakerConfig(failure_threshold=3, reset_timeout_ms=1000)
        cb = CircuitBreaker("test", config)

        # Pattern: fail, success (resets), fail, success (resets), fail
        operations = [
            AsyncMock(side_effect=Exception("error")),  # failure_count = 1
            AsyncMock(return_value="ok"),               # failure_count = 0 (reset)
            AsyncMock(side_effect=Exception("error")),  # failure_count = 1
            AsyncMock(return_value="ok"),               # failure_count = 0 (reset)
            AsyncMock(side_effect=Exception("error")),  # failure_count = 1
        ]

        for fn in operations:
            try:
                await cb.execute(fn)
            except:
                pass

        # Should have 1 failure from last operation
        state = cb.get_state()
        assert state.failure_count == 1
        assert state.is_open is False  # Threshold not reached


class TestConcurrency:
    """Test concurrent operations"""

    @pytest.mark.asyncio
    async def test_concurrent_retry_calls(self):
        """Test concurrent retry operations"""
        fn = AsyncMock(return_value="success")
        config = RetryConfig(max_attempts=3, initial_delay_ms=10)

        # Run multiple concurrent retries
        tasks = [with_retry(fn, config) for _ in range(5)]
        results = await asyncio.gather(*tasks)

        assert len(results) == 5
        assert all(r == "success" for r in results)

    @pytest.mark.asyncio
    async def test_concurrent_circuit_breaker_calls(self):
        """Test concurrent circuit breaker calls"""
        cb = CircuitBreaker("test")
        fn = AsyncMock(return_value="ok")

        # Concurrent calls
        tasks = [cb.execute(fn) for _ in range(5)]
        results = await asyncio.gather(*tasks)

        assert len(results) == 5
        assert all(r == "ok" for r in results)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
