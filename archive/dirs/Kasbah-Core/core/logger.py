"""
Enterprise-grade logging utility
Structured logging with levels, context, and error tracking
Ported from test2/src/lib/logger.ts
"""

import json
import time
import logging
import sys
import traceback
from typing import Optional, Dict, Any, Callable, Union
from datetime import datetime, timezone
from enum import Enum
from dataclasses import dataclass, asdict
import os
import random
import string


class LogLevel(str, Enum):
    """Log level enumeration"""
    DEBUG = 'debug'
    INFO = 'info'
    WARN = 'warn'
    ERROR = 'error'
    CRITICAL = 'critical'


class LogCategory(str, Enum):
    """Log category enumeration"""
    API = 'api'
    DETECTION = 'detection'
    VALIDATION = 'validation'
    SECURITY = 'security'
    SYSTEM = 'system'
    PERFORMANCE = 'performance'


# Minimum log level based on environment
MIN_LEVEL: LogLevel = LogLevel.INFO if os.getenv('NODE_ENV') == 'production' else LogLevel.DEBUG

# Level priority
LEVEL_PRIORITY: Dict[LogLevel, int] = {
    LogLevel.DEBUG: 0,
    LogLevel.INFO: 1,
    LogLevel.WARN: 2,
    LogLevel.ERROR: 3,
    LogLevel.CRITICAL: 4,
}

# ANSI color codes for terminal
LEVEL_COLORS: Dict[LogLevel, str] = {
    LogLevel.DEBUG: '\x1b[36m',      # Cyan
    LogLevel.INFO: '\x1b[32m',       # Green
    LogLevel.WARN: '\x1b[33m',       # Yellow
    LogLevel.ERROR: '\x1b[31m',      # Red
    LogLevel.CRITICAL: '\x1b[35m',   # Magenta
}

RESET_COLOR = '\x1b[0m'


@dataclass
class LogError:
    """Error information for log entry"""
    name: str
    message: str
    stack: Optional[str] = None


@dataclass
class LogEntry:
    """Log entry structure"""
    timestamp: str
    level: str
    category: str
    message: str
    context: Optional[Dict[str, Any]] = None
    error: Optional[Dict[str, Any]] = None
    duration: Optional[int] = None
    request_id: Optional[str] = None


def format_timestamp() -> str:
    """
    Format current timestamp as ISO string

    Returns:
        ISO format timestamp string
    """
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def format_entry(entry: LogEntry) -> str:
    """
    Format log entry for human-readable output

    Args:
        entry: LogEntry to format

    Returns:
        Formatted log string with colors
    """
    color = LEVEL_COLORS.get(LogLevel(entry.level), '')
    level_str = entry.level.upper().ljust(8)

    message = f"{color}[{entry.timestamp}] [{level_str}] [{entry.category.upper()}]{RESET_COLOR} {entry.message}"

    if entry.context and len(entry.context) > 0:
        context_str = json.dumps(entry.context, indent=2)
        message += f"\n  Context: {context_str}"

    if entry.error:
        message += f"\n  Error: {entry.error.get('name', 'Unknown')}: {entry.error.get('message', '')}"
        if entry.error.get('stack'):
            message += f"\n  Stack: {entry.error['stack']}"

    if entry.duration is not None:
        message += f"\n  Duration: {entry.duration}ms"

    return message


def sanitize_context(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize context to remove sensitive data

    Args:
        context: Context dictionary to sanitize

    Returns:
        Sanitized context dictionary
    """
    if not isinstance(context, dict):
        return context

    sanitized = dict(context)
    sensitive_keys = ['password', 'token', 'secret', 'key', 'credential', 'auth']

    for key in list(sanitized.keys()):
        # Check for sensitive key names
        if any(sk in key.lower() for sk in sensitive_keys):
            sanitized[key] = '[REDACTED]'
        # Truncate large string values
        elif isinstance(sanitized[key], str) and len(sanitized[key]) > 1000:
            sanitized[key] = sanitized[key][:1000] + '... [truncated]'
        # Recursively sanitize nested dicts
        elif isinstance(sanitized[key], dict) and not isinstance(sanitized[key], type):
            sanitized[key] = sanitize_context(sanitized[key])

    return sanitized


def handle_critical_error(entry: LogEntry) -> None:
    """
    Handle critical errors with prominent output

    Args:
        entry: LogEntry for critical error
    """
    separator = '=' * 60
    print(f"\n{separator}")
    print("CRITICAL ERROR DETECTED")
    print(separator)
    print(json.dumps(asdict(entry), indent=2, default=str))
    print(f"{separator}\n")


def log(
    level: LogLevel,
    category: LogCategory,
    message: str,
    context: Optional[Dict[str, Any]] = None,
    error: Optional[Exception] = None,
    duration: Optional[int] = None,
    request_id: Optional[str] = None,
) -> None:
    """
    Core logging function

    Args:
        level: Log level
        category: Log category
        message: Log message
        context: Context data
        error: Exception object
        duration: Operation duration in milliseconds
        request_id: Request identifier
    """
    # Check if level should be logged
    if LEVEL_PRIORITY[level] < LEVEL_PRIORITY[MIN_LEVEL]:
        return

    entry = LogEntry(
        timestamp=format_timestamp(),
        level=level.value,
        category=category.value,
        message=message,
        context=sanitize_context(context) if context else None,
        duration=duration,
        request_id=request_id,
    )

    if error:
        # Get traceback if available
        tb_str = ''
        if hasattr(error, '__traceback__') and error.__traceback__:
            tb_str = ''.join(traceback.format_tb(error.__traceback__))

        entry.error = {
            'name': error.__class__.__name__,
            'message': str(error),
            'stack': tb_str
        }

    # In production, output JSON for log aggregation
    if os.getenv('NODE_ENV') == 'production':
        print(json.dumps(asdict(entry), indent=None, default=str))
    else:
        print(format_entry(entry))

    # Critical errors should trigger alerts
    if level == LogLevel.CRITICAL:
        handle_critical_error(entry)


class Logger:
    """
    Logger class with chainable methods
    """

    def __init__(self, category: LogCategory, request_id: Optional[str] = None):
        """
        Initialize Logger

        Args:
            category: Log category
            request_id: Optional request identifier
        """
        self.category = category
        self.request_id = request_id

    def set_request_id(self, request_id: str) -> 'Logger':
        """
        Set request ID (chainable)

        Args:
            request_id: Request identifier

        Returns:
            Self for chaining
        """
        self.request_id = request_id
        return self

    def debug(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """Log debug message"""
        log(LogLevel.DEBUG, self.category, message, context, None, None, self.request_id)

    def info(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """Log info message"""
        log(LogLevel.INFO, self.category, message, context, None, None, self.request_id)

    def warn(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """Log warning message"""
        log(LogLevel.WARN, self.category, message, context, None, None, self.request_id)

    def error(
        self,
        message: str,
        error: Optional[Exception] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log error message"""
        log(LogLevel.ERROR, self.category, message, context, error, None, self.request_id)

    def critical(
        self,
        message: str,
        error: Optional[Exception] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log critical message"""
        log(LogLevel.CRITICAL, self.category, message, context, error, None, self.request_id)

    def time(self, label: str, fn: Callable) -> Any:
        """
        Time an operation (sync or async)

        Args:
            label: Operation label
            fn: Function to time

        Returns:
            Result of function
        """
        import asyncio
        import inspect

        start = time.time() * 1000  # Convert to milliseconds

        try:
            result = fn()

            # Handle async functions
            if inspect.iscoroutine(result):
                async def timed_async():
                    try:
                        res = await result
                        duration = int(time.time() * 1000 - start)
                        log(
                            LogLevel.INFO,
                            self.category,
                            f"Operation completed: {label}",
                            None,
                            None,
                            duration,
                            self.request_id
                        )
                        return res
                    except Exception as e:
                        duration = int(time.time() * 1000 - start)
                        log(
                            LogLevel.ERROR,
                            self.category,
                            f"Operation failed: {label}",
                            None,
                            e,
                            duration,
                            self.request_id
                        )
                        raise

                return timed_async()

            # Handle sync functions
            duration = int(time.time() * 1000 - start)
            log(
                LogLevel.INFO,
                self.category,
                f"Operation completed: {label}",
                None,
                None,
                duration,
                self.request_id
            )
            return result

        except Exception as e:
            duration = int(time.time() * 1000 - start)
            log(
                LogLevel.ERROR,
                self.category,
                f"Operation failed: {label}",
                None,
                e,
                duration,
                self.request_id
            )
            raise


def create_logger(category: LogCategory, request_id: Optional[str] = None) -> Logger:
    """
    Create a logger for a specific category

    Args:
        category: Log category
        request_id: Optional request identifier

    Returns:
        Logger instance
    """
    return Logger(category, request_id)


# Pre-configured loggers
api_logger = create_logger(LogCategory.API)
detection_logger = create_logger(LogCategory.DETECTION)
validation_logger = create_logger(LogCategory.VALIDATION)
security_logger = create_logger(LogCategory.SECURITY)
system_logger = create_logger(LogCategory.SYSTEM)
performance_logger = create_logger(LogCategory.PERFORMANCE)


def generate_request_id() -> str:
    """
    Generate unique request ID

    Returns:
        Unique request identifier
    """
    timestamp_part = format(int(time.time() * 1000), 'x')
    random_part = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"req_{timestamp_part}_{random_part}"


def log_request(
    method: str,
    path: str,
    request_id: str,
    metadata: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log API request

    Args:
        method: HTTP method
        path: Request path
        request_id: Request identifier
        metadata: Additional metadata
    """
    context = {
        'method': method,
        'path': path,
        **(metadata or {})
    }

    api_logger.set_request_id(request_id).info(
        f"Request: {method} {path}",
        context
    )


def log_response(
    method: str,
    path: str,
    status_code: int,
    duration: int,
    request_id: str
) -> None:
    """
    Log API response

    Args:
        method: HTTP method
        path: Request path
        status_code: HTTP status code
        duration: Response time in milliseconds
        request_id: Request identifier
    """
    # Determine log level based on status code
    if status_code >= 500:
        level = LogLevel.ERROR
    elif status_code >= 400:
        level = LogLevel.WARN
    else:
        level = LogLevel.INFO

    log(
        level,
        LogCategory.API,
        f"Response: {method} {path} - {status_code}",
        {
            'method': method,
            'path': path,
            'statusCode': status_code,
            'duration': duration
        },
        None,
        duration,
        request_id
    )
