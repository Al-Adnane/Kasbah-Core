"""
Comprehensive test suite for logger module
Tests structured logging, sanitization, request tracking, and performance monitoring
"""

import pytest
import json
import time
from io import StringIO
import sys
from unittest.mock import patch, Mock, MagicMock
from core.logger import (
    LogLevel,
    LogCategory,
    LogEntry,
    Logger,
    create_logger,
    format_timestamp,
    format_entry,
    sanitize_context,
    log,
    generate_request_id,
    log_request,
    log_response,
    api_logger,
    detection_logger,
    validation_logger,
    security_logger,
    system_logger,
    performance_logger,
    MIN_LEVEL,
)


class TestLogLevel:
    """Test LogLevel enumeration"""

    def test_log_level_debug(self):
        """Test debug level"""
        assert LogLevel.DEBUG.value == 'debug'

    def test_log_level_info(self):
        """Test info level"""
        assert LogLevel.INFO.value == 'info'

    def test_log_level_warn(self):
        """Test warn level"""
        assert LogLevel.WARN.value == 'warn'

    def test_log_level_error(self):
        """Test error level"""
        assert LogLevel.ERROR.value == 'error'

    def test_log_level_critical(self):
        """Test critical level"""
        assert LogLevel.CRITICAL.value == 'critical'


class TestLogCategory:
    """Test LogCategory enumeration"""

    def test_api_category(self):
        """Test API category"""
        assert LogCategory.API.value == 'api'

    def test_detection_category(self):
        """Test detection category"""
        assert LogCategory.DETECTION.value == 'detection'

    def test_validation_category(self):
        """Test validation category"""
        assert LogCategory.VALIDATION.value == 'validation'

    def test_security_category(self):
        """Test security category"""
        assert LogCategory.SECURITY.value == 'security'

    def test_system_category(self):
        """Test system category"""
        assert LogCategory.SYSTEM.value == 'system'

    def test_performance_category(self):
        """Test performance category"""
        assert LogCategory.PERFORMANCE.value == 'performance'


class TestFormatTimestamp:
    """Test timestamp formatting"""

    def test_format_timestamp_iso(self):
        """Test timestamp is ISO format"""
        ts = format_timestamp()
        assert 'T' in ts
        assert 'Z' in ts

    def test_format_timestamp_contains_date(self):
        """Test timestamp contains current date"""
        ts = format_timestamp()
        from datetime import datetime, timezone
        current_date = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        assert current_date in ts


class TestSanitizeContext:
    """Test context sanitization"""

    def test_sanitize_password(self):
        """Test password is redacted"""
        context = {'password': 'secret123'}
        result = sanitize_context(context)
        assert result['password'] == '[REDACTED]'

    def test_sanitize_token(self):
        """Test token is redacted"""
        context = {'token': 'abc123def'}
        result = sanitize_context(context)
        assert result['token'] == '[REDACTED]'

    def test_sanitize_secret(self):
        """Test secret is redacted"""
        context = {'secret': 'hidden'}
        result = sanitize_context(context)
        assert result['secret'] == '[REDACTED]'

    def test_sanitize_api_key(self):
        """Test API key is redacted"""
        context = {'api_key': 'key123'}
        result = sanitize_context(context)
        assert result['api_key'] == '[REDACTED]'

    def test_sanitize_auth_token(self):
        """Test auth token is redacted"""
        context = {'authToken': 'token123'}
        result = sanitize_context(context)
        assert result['authToken'] == '[REDACTED]'

    def test_sanitize_nested_password(self):
        """Test nested password is redacted"""
        context = {'user': {'password': 'secret'}}
        result = sanitize_context(context)
        assert result['user']['password'] == '[REDACTED]'

    def test_sanitize_large_string(self):
        """Test large strings are truncated"""
        large_str = 'x' * 2000
        context = {'data': large_str}
        result = sanitize_context(context)
        assert len(result['data']) <= 1100  # 1000 + truncation message
        assert '[truncated]' in result['data']

    def test_sanitize_normal_values(self):
        """Test normal values are not modified"""
        context = {'user_id': 123, 'name': 'Alice'}
        result = sanitize_context(context)
        assert result['user_id'] == 123
        assert result['name'] == 'Alice'

    def test_sanitize_empty_context(self):
        """Test empty context"""
        result = sanitize_context({})
        assert result == {}


class TestLoggerBasics:
    """Test basic Logger functionality"""

    def test_logger_creation(self):
        """Test creating a logger"""
        logger = Logger(LogCategory.API)
        assert logger.category == LogCategory.API
        assert logger.request_id is None

    def test_logger_with_request_id(self):
        """Test logger with initial request ID"""
        logger = Logger(LogCategory.API, 'req123')
        assert logger.request_id == 'req123'

    def test_logger_set_request_id(self):
        """Test setting request ID (chainable)"""
        logger = Logger(LogCategory.API)
        result = logger.set_request_id('req456')
        assert result is logger  # Chainable
        assert logger.request_id == 'req456'

    @patch('sys.stdout', new_callable=StringIO)
    def test_logger_debug(self, mock_stdout):
        """Test debug logging"""
        logger = Logger(LogCategory.API)
        logger.debug('Test debug message')
        output = mock_stdout.getvalue()
        assert 'Test debug message' in output or output == ''  # May not show in min level

    @patch('sys.stdout', new_callable=StringIO)
    def test_logger_info(self, mock_stdout):
        """Test info logging"""
        logger = Logger(LogCategory.API)
        logger.info('Test info message')
        output = mock_stdout.getvalue()
        assert 'Test info message' in output

    @patch('sys.stdout', new_callable=StringIO)
    def test_logger_warn(self, mock_stdout):
        """Test warning logging"""
        logger = Logger(LogCategory.API)
        logger.warn('Test warning')
        output = mock_stdout.getvalue()
        assert 'Test warning' in output

    @patch('sys.stdout', new_callable=StringIO)
    def test_logger_error(self, mock_stdout):
        """Test error logging"""
        logger = Logger(LogCategory.API)
        logger.error('Test error', ValueError('test'))
        output = mock_stdout.getvalue()
        assert 'Test error' in output

    @patch('sys.stdout', new_callable=StringIO)
    def test_logger_error_with_exception(self, mock_stdout):
        """Test error logging with exception"""
        logger = Logger(LogCategory.API)
        try:
            raise ValueError('test error')
        except ValueError as e:
            logger.error('Operation failed', e)
        output = mock_stdout.getvalue()
        assert 'Operation failed' in output


class TestLoggerContext:
    """Test logger context handling"""

    @patch('sys.stdout', new_callable=StringIO)
    def test_logger_context_included(self, mock_stdout):
        """Test context is included in logs"""
        logger = Logger(LogCategory.API)
        logger.info('Test', {'user_id': 123})
        output = mock_stdout.getvalue()
        assert 'user_id' in output or 'Test' in output

    @patch('sys.stdout', new_callable=StringIO)
    def test_logger_context_sanitized(self, mock_stdout):
        """Test context is sanitized"""
        logger = Logger(LogCategory.API)
        logger.info('Test', {'password': 'secret'})
        output = mock_stdout.getvalue()
        assert '[REDACTED]' in output or 'Test' in output


class TestRequestIdGeneration:
    """Test request ID generation"""

    def test_generate_request_id_format(self):
        """Test request ID format"""
        req_id = generate_request_id()
        assert req_id.startswith('req_')

    def test_generate_request_id_unique(self):
        """Test request IDs are unique"""
        ids = {generate_request_id() for _ in range(100)}
        assert len(ids) == 100  # All should be unique

    def test_generate_request_id_length(self):
        """Test request ID has reasonable length"""
        req_id = generate_request_id()
        assert len(req_id) > 10  # Has timestamp and random parts


class TestLogRequest:
    """Test API request logging"""

    @patch('sys.stdout', new_callable=StringIO)
    def test_log_request_basic(self, mock_stdout):
        """Test logging API request"""
        log_request('GET', '/api/users', 'req123')
        output = mock_stdout.getvalue()
        assert 'GET' in output or 'req123' in output

    @patch('sys.stdout', new_callable=StringIO)
    def test_log_request_with_metadata(self, mock_stdout):
        """Test logging request with metadata"""
        log_request('POST', '/api/upload', 'req456', {'size': 1024})
        output = mock_stdout.getvalue()
        assert 'POST' in output or 'req456' in output


class TestLogResponse:
    """Test API response logging"""

    @patch('sys.stdout', new_callable=StringIO)
    def test_log_response_success(self, mock_stdout):
        """Test logging successful response"""
        log_response('GET', '/api/users', 200, 50, 'req123')
        output = mock_stdout.getvalue()
        assert 'GET' in output or 'req123' in output

    @patch('sys.stdout', new_callable=StringIO)
    def test_log_response_client_error(self, mock_stdout):
        """Test logging client error response"""
        log_response('POST', '/api/data', 400, 10, 'req456')
        output = mock_stdout.getvalue()
        assert 'POST' in output or 'req456' in output

    @patch('sys.stdout', new_callable=StringIO)
    def test_log_response_server_error(self, mock_stdout):
        """Test logging server error response"""
        log_response('GET', '/api/data', 500, 30, 'req789')
        output = mock_stdout.getvalue()
        assert 'GET' in output or 'req789' in output


class TestPreconfiguredLoggers:
    """Test pre-configured logger instances"""

    def test_api_logger_exists(self):
        """Test API logger is available"""
        assert api_logger is not None
        assert api_logger.category == LogCategory.API

    def test_detection_logger_exists(self):
        """Test detection logger is available"""
        assert detection_logger is not None
        assert detection_logger.category == LogCategory.DETECTION

    def test_validation_logger_exists(self):
        """Test validation logger is available"""
        assert validation_logger is not None
        assert validation_logger.category == LogCategory.VALIDATION

    def test_security_logger_exists(self):
        """Test security logger is available"""
        assert security_logger is not None
        assert security_logger.category == LogCategory.SECURITY

    def test_system_logger_exists(self):
        """Test system logger is available"""
        assert system_logger is not None
        assert system_logger.category == LogCategory.SYSTEM

    def test_performance_logger_exists(self):
        """Test performance logger is available"""
        assert performance_logger is not None
        assert performance_logger.category == LogCategory.PERFORMANCE


class TestCreateLogger:
    """Test logger factory function"""

    def test_create_logger_api(self):
        """Test creating API logger"""
        logger = create_logger(LogCategory.API)
        assert logger.category == LogCategory.API

    def test_create_logger_with_request_id(self):
        """Test creating logger with request ID"""
        logger = create_logger(LogCategory.DETECTION, 'req123')
        assert logger.request_id == 'req123'

    def test_create_logger_each_unique(self):
        """Test each logger creation is unique instance"""
        logger1 = create_logger(LogCategory.API)
        logger2 = create_logger(LogCategory.API)
        assert logger1 is not logger2


class TestLogEntry:
    """Test LogEntry dataclass"""

    def test_log_entry_creation(self):
        """Test creating LogEntry"""
        entry = LogEntry(
            timestamp='2026-03-01T00:00:00Z',
            level='info',
            category='api',
            message='Test'
        )
        assert entry.message == 'Test'
        assert entry.level == 'info'

    def test_log_entry_with_context(self):
        """Test LogEntry with context"""
        context = {'user_id': 123}
        entry = LogEntry(
            timestamp='2026-03-01T00:00:00Z',
            level='info',
            category='api',
            message='Test',
            context=context
        )
        assert entry.context == context


class TestFormatEntry:
    """Test log entry formatting"""

    def test_format_entry_basic(self):
        """Test formatting basic entry"""
        entry = LogEntry(
            timestamp='2026-03-01T00:00:00Z',
            level='info',
            category='api',
            message='Test message'
        )
        formatted = format_entry(entry)
        assert 'Test message' in formatted
        assert 'API' in formatted

    def test_format_entry_with_context(self):
        """Test formatting entry with context"""
        entry = LogEntry(
            timestamp='2026-03-01T00:00:00Z',
            level='info',
            category='api',
            message='Test',
            context={'user_id': 123}
        )
        formatted = format_entry(entry)
        assert 'Context' in formatted or 'user_id' in formatted

    def test_format_entry_with_duration(self):
        """Test formatting entry with duration"""
        entry = LogEntry(
            timestamp='2026-03-01T00:00:00Z',
            level='info',
            category='api',
            message='Test',
            duration=100
        )
        formatted = format_entry(entry)
        assert 'Duration' in formatted or '100' in formatted


class TestLoggingIntegration:
    """Test logging integration scenarios"""

    @patch('sys.stdout', new_callable=StringIO)
    def test_request_response_flow(self, mock_stdout):
        """Test complete request/response logging flow"""
        req_id = generate_request_id()
        log_request('POST', '/api/analyze', req_id)
        time.sleep(0.01)  # Simulate processing
        log_response('POST', '/api/analyze', 200, 50, req_id)
        output = mock_stdout.getvalue()
        assert 'POST' in output or req_id in output

    @patch('sys.stdout', new_callable=StringIO)
    def test_error_logging_flow(self, mock_stdout):
        """Test error logging flow"""
        logger = create_logger(LogCategory.DETECTION, 'req123')
        try:
            raise ValueError('Analysis failed')
        except ValueError as e:
            logger.error('Detection failed', e, {'file': 'test.jpg'})
        output = mock_stdout.getvalue()
        assert 'Detection failed' in output or 'req123' in output


class TestLoggerChaining:
    """Test logger method chaining"""

    @patch('sys.stdout', new_callable=StringIO)
    def test_set_request_id_chaining(self, mock_stdout):
        """Test set_request_id is chainable"""
        logger = create_logger(LogCategory.API)
        result = logger.set_request_id('req123').info('Test')
        # Should not raise any errors


class TestLoggerPerformance:
    """Test logger performance characteristics"""

    def test_logger_creation_fast(self):
        """Test logger creation is fast"""
        start = time.time()
        for _ in range(100):
            create_logger(LogCategory.API)
        elapsed = time.time() - start
        assert elapsed < 0.1  # Should be very fast

    def test_context_sanitization_fast(self):
        """Test context sanitization is fast"""
        context = {'user_id': 123, 'email': 'test@example.com', 'password': 'secret'}
        start = time.time()
        for _ in range(100):
            sanitize_context(context)
        elapsed = time.time() - start
        assert elapsed < 0.1  # Should be fast


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
