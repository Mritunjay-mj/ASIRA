"""
Logging configuration for ASIRA

Sets up unified logging with configurable levels,
formatting, and output destinations including file and console.

Version: 1.0.0
Last updated: 2025-03-15
"""
import os
import sys
import logging
import logging.handlers
import json
from pathlib import Path
from typing import Dict, Any, Optional, List

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
    app_name: str = "ASIRA"
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
        new_context.update
