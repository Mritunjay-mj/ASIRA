"""
Logging configuration for ASIRA

Sets up unified logging with configurable levels,
formatting, and output destinations including file and console.

Version: 1.0.0
Last updated: 2025-03-15 17:22:45
Last updated by: Rahul
"""
import os
import sys
import logging
import logging.handlers
import json
import time
import uuid
import functools
import threading
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable, Union, TypeVar, cast
from contextlib import contextmanager

# Import settings if available
try:
    from src.common.config import settings
except ImportError:
    settings = None

# Custom log record serializer for JSON formatting
def _json_log_formatter(record: logging.LogRecord) -> Dict[str, Any]:
    """
    Format a log record as a JSON-serializable dictionary
    
    Args:
        record: LogRecord to format
        
    Returns:
        Dictionary with log record data
    """
    data = {
        "timestamp": record.created,
        "level": record.levelname,
        "logger": record.name,
        "message": record.getMessage(),
        "path": f"{record.pathname}:{record.lineno}",
        "function": record.funcName
    }
    
    # Add exception info if present
    if record.exc_info:
        data["exception"] = {
            "type": record.exc_info[0].__name__,
            "message": str(record.exc_info[1]),
            "traceback": record.exc_text or ""
        }
    
    # Add extra attributes
    if hasattr(record, "data") and record.data:
        data["data"] = record.data
        
    # Add request_id if available
    if hasattr(record, "request_id"):
        data["request_id"] = record.request_id
        
    # Add correlation_id if available
    if hasattr(record, "correlation_id"):
        data["correlation_id"] = record.correlation_id
        
    # Add duration if available for performance logging
    if hasattr(record, "duration_ms"):
        data["duration_ms"] = record.duration_ms
        
    # Add component if available
    if hasattr(record, "component"):
        data["component"] = record.component
        
    return data


class JsonFormatter(logging.Formatter):
    """JSON formatter for log records"""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format the log record as JSON"""
        data = _json_log_formatter(record)
        return json.dumps(data)


class LoggerAdapter(logging.LoggerAdapter):
    """Logger adapter that adds context data to log records"""
    
    def process(self, msg, kwargs):
        """Process log record with context data"""
        if "extra" not in kwargs:
            kwargs["extra"] = {}
        if "data" not in kwargs["extra"]:
            kwargs["extra"]["data"] = {}
            
        # Add context data
        if self.extra:
            kwargs["extra"]["data"].update(self.extra)
            
        return msg, kwargs


def configure_logging(
    log_level: str = "INFO",
    log_format: str = "standard",  # Options: standard, json
    log_dir: Optional[str] = "logs",
    log_file: Optional[str] = "asira.log",
    max_size_mb: int = 10,
    backup_count: int = 5,
    console_output: bool = True,
    app_name: str = "ASIRA",
    capture_warnings: bool = True,
    suppress_loggers: Optional[List[str]] = None
) -> None:
    """
    Configure logging for the application
    
    Args:
        log_level: Minimum log level to display
        log_format: Log format (standard or json)
        log_dir: Directory for log files (None for no file logging)
        log_file: Log file name
        max_size_mb: Maximum log file size in MB
        backup_count: Number of backup files to keep
        console_output: Whether to output logs to console
        app_name: Application name for logging
        capture_warnings: Whether to capture warnings through logging
        suppress_loggers: List of logger names to suppress
    """
    # Convert string log level to logging constant
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")
    
    # Create root logger and set level
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Clear any existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create formatters
    if log_format.lower() == "json":
        formatter = JsonFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    # Configure file handler
    if log_dir:
        try:
            # Create logs directory if it doesn't exist
            log_path = Path(log_dir)
            log_path.mkdir(parents=True, exist_ok=True)
            
            # Create rotating file handler
            file_handler = logging.handlers.RotatingFileHandler(
                log_path / log_file,
                maxBytes=max_size_mb * 1024 * 1024,
                backupCount=backup_count,
                encoding='utf-8'
            )
            file_handler.setLevel(numeric_level)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
        except Exception as e:
            print(f"Error configuring file logging: {e}")
    
    # Configure console handler
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(numeric_level)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
    
    # Configure module-specific loggers
    loggers = [
        "asira",
        "asira.api",
        "asira.detection",
        "asira.response",
        "asira.database",
        "asira.security"
    ]
    
    for logger_name in loggers:
        logger = logging.getLogger(logger_name)
        logger.setLevel(numeric_level)
        logger.propagate = True
    
    # Suppress certain loggers if specified
    if suppress_loggers:
        for logger_name in suppress_loggers:
            logger = logging.getLogger(logger_name)
            logger.setLevel(logging.WARNING)  # Only show warnings and above
    
    # Capture Python warnings
    if capture_warnings:
        logging.captureWarnings(True)
    
    # Log startup message
    startup_logger = logging.getLogger("asira")
    startup_logger.info(f"{app_name} logging initialized with level {log_level}")


def get_logger(name: str, context: Optional[Dict[str, Any]] = None) -> LoggerAdapter:
    """
    Get a logger with optional context data
    
    Args:
        name: Logger name
        context: Optional context data to include in all log messages
        
    Returns:
        LoggerAdapter instance
    """
    logger = logging.getLogger(name)
    return LoggerAdapter(logger, context or {})


def log_with_context(
    logger: logging.Logger, 
    level: int, 
    message: str, 
    context: Optional[Dict[str, Any]] = None, 
    exc_info: Any = None
) -> None:
    """
    Log a message with context data
    
    Args:
        logger: Logger to use
        level: Log level
        message: Log message
        context: Context data to include
        exc_info: Exception info
    """
    extra = {"data": context or {}}
    logger.log(level, message, extra=extra, exc_info=exc_info)


class ContextLogger:
    """Context-aware logger that can be used as a context manager"""
    
    def __init__(self, logger: logging.Logger, context: Optional[Dict[str, Any]] = None):
        """
        Initialize with a logger and optional context
        
        Args:
            logger: Base logger
            context: Initial context data
        """
        self.logger = logger
        self.context = context or {}
        
    def with_context(self, **kwargs) -> "ContextLogger":
        """
        Create a new logger with additional context
        
        Args:
            **kwargs: Context data to add
            
        Returns:
            New ContextLogger instance with combined context
        """
        new_context = self.context.copy()
        new_context.update(kwargs)
        return ContextLogger(self.logger, new_context)
    
    def debug(self, message: str, **kwargs) -> None:
        """Log a debug message with context"""
        context = self.context.copy()
        context.update(kwargs)
        log_with_context(self.logger, logging.DEBUG, message, context)
        
    def info(self, message: str, **kwargs) -> None:
        """Log an info message with context"""
        context = self.context.copy()
        context.update(kwargs)
        log_with_context(self.logger, logging.INFO, message, context)
        
    def warning(self, message: str, **kwargs) -> None:
        """Log a warning message with context"""
        context = self.context.copy()
        context.update(kwargs)
        log_with_context(self.logger, logging.WARNING, message, context)
        
    def error(self, message: str, exc_info: Any = None, **kwargs) -> None:
        """Log an error message with context"""
        context = self.context.copy()
        context.update(kwargs)
        log_with_context(self.logger, logging.ERROR, message, context, exc_info=exc_info)
        
    def critical(self, message: str, exc_info: Any = None, **kwargs) -> None:
        """Log a critical message with context"""
        context = self.context.copy()
        context.update(kwargs)
        log_with_context(self.logger, logging.CRITICAL, message, context, exc_info=exc_info)
        
    def exception(self, message: str, **kwargs) -> None:
        """Log an exception message with context and exception info"""
        context = self.context.copy()
        context.update(kwargs)
        log_with_context(self.logger, logging.ERROR, message, context, exc_info=True)
    
    @contextmanager
    def span(self, operation_name: str, **kwargs):
        """
        Create a logging span for timing operations
        
        Args:
            operation_name: Name of the operation being performed
            **kwargs: Additional context for the span
            
        Yields:
            None
        """
        start_time = time.time()
        span_context = self.context.copy()
        span_context.update(kwargs)
        span_context["operation"] = operation_name
        
        try:
            yield
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            span_context["duration_ms"] = round(duration_ms, 2)
            span_context["error"] = str(e)
            span_context["exception_type"] = e.__class__.__name__
            self.exception(f"Error in {operation_name}", **span_context)
            raise
        else:
            duration_ms = (time.time() - start_time) * 1000
            span_context["duration_ms"] = round(duration_ms, 2)
            self.info(f"Completed {operation_name}", **span_context)


# Type variable for function return type
T = TypeVar('T')

def log_execution_time(logger: Union[logging.Logger, str], level: int = logging.INFO):
    """
    Decorator to log execution time of a function
    
    Args:
        logger: Logger instance or logger name
        level: Log level for the message
        
    Returns:
        Decorator function
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            # Get logger if string was provided
            actual_logger = logger if isinstance(logger, logging.Logger) else logging.getLogger(logger)
            
            start_time = time.time()
            try:
                return func(*args, **kwargs)
            finally:
                execution_time = time.time() - start_time
                actual_logger.log(
                    level, 
                    f"Function '{func.__name__}' executed in {execution_time:.4f} seconds",
                    extra={"duration_ms": execution_time * 1000}
                )
        return wrapper
    return decorator


class RequestIdFilter(logging.Filter):
    """Filter that adds request ID to log records"""
    
    _request_id_storage = threading.local()
    
    @classmethod
    def get_request_id(cls) -> str:
        """Get current request ID or generate a new one"""
        if not hasattr(cls._request_id_storage, "request_id"):
            cls._request_id_storage.request_id = str(uuid.uuid4())
        return cls._request_id_storage.request_id
    
    @classmethod
    def set_request_id(cls, request_id: str) -> None:
        """Set request ID for current thread"""
        cls._request_id_storage.request_id = request_id
    
    @classmethod
    def clear_request_id(cls) -> None:
        """Clear request ID for current thread"""
        if hasattr(cls._request_id_storage, "request_id"):
            delattr(cls._request_id_storage, "request_id")
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Add request_id to record"""
        record.request_id = self.get_request_id()
        return True


@contextmanager
def request_context(request_id: Optional[str] = None):
    """
    Context manager for request logging
    
    Args:
        request_id: Optional request ID, generated if not provided
        
    Yields:
        Request ID
    """
    if request_id is None:
        request_id = str(uuid.uuid4())
    
    # Set request ID in thread local storage
    RequestIdFilter.set_request_id(request_id)
    
    try:
        yield request_id
    finally:
        RequestIdFilter.clear_request_id()


@contextmanager
def temporary_log_level(logger_name: str, level: int):
    """
    Temporarily change log level for a logger
    
    Args:
        logger_name: Name of logger to modify
        level: Temporary log level
        
    Yields:
        None
    """
    logger = logging.getLogger(logger_name)
    old_level = logger.level
    
    try:
        logger.setLevel(level)
        yield
    finally:
        logger.setLevel(old_level)


def add_file_handler(logger: logging.Logger, file_path: str, log_level: int = logging.INFO):
    """
    Add a file handler to a logger
    
    Args:
        logger: Logger to add handler to
        file_path: Path to log file
        log_level: Log level for the handler
    """
    # Create directory if it doesn't exist
    log_dir = os.path.dirname(file_path)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    
    # Create handler
    handler = logging.FileHandler(file_path)
    handler.setLevel(log_level)
    
    # Add formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    
    # Add handler to logger
    logger.addHandler(handler)


def configure_from_settings():
    """
    Configure logging from application settings
    """
    if not settings:
        print("WARNING: Settings module not available, using default logging configuration")
        configure_logging()
        return
    
    # Determine log directory
    log_dir = settings.log_dir if hasattr(settings, 'log_dir') else "logs"
    
    # Get log level from settings
    log_level = settings.log_level if hasattr(settings, 'log_level') else "INFO"
    
    # Determine if we should use JSON logging
    use_json = settings.environment == "production" if hasattr(settings, 'environment') else False
    log_format = "json" if use_json else "standard"
    
    # Configure logging
    configure_logging(
        log_level=log_level,
        log_format=log_format,
        log_dir=log_dir,
        log_file="asira.log",
        max_size_mb=50,
        backup_count=10,
        console_output=True,
        app_name=settings.app_name if hasattr(settings, 'app_name') else "ASIRA",
        suppress_loggers=[
            "elasticsearch",
            "urllib3.connectionpool",
            "asyncio",
            "sqlalchemy.engine"
        ]
    )


# Initialize a basic logger for this module
module_logger = logging.getLogger("asira.logging")

# Module version information
LOGGING_VERSION = "1.0.0"
LOGGING_LAST_UPDATED = "2025-03-15 17:22:45"
LOGGING_LAST_UPDATED_BY = "Rahul"
