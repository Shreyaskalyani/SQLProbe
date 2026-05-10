"""
Logging System Module
=====================

Provides structured logging with debug mode and request/response tracing.
"""

import logging
import sys
from typing import Optional
from pathlib import Path
from datetime import datetime


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for different log levels."""
    
    COLORS = {
        'DEBUG': '\033[36m',
        'INFO': '\033[32m',
        'WARNING': '\033[33m',
        'ERROR': '\033[31m',
        'CRITICAL': '\033[35m',
    }
    RESET = '\033[0m'
    
    def format(self, record):
        if hasattr(sys.stdout, 'fileno') and sys.stdout.isatty():
            color = self.COLORS.get(record.levelname, '')
            record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


class RequestResponseFormatter(logging.Formatter):
    """Formatter for request/response logging."""
    
    def format(self, record):
        msg = record.getMessage()
        if record.name.startswith('httpx'):
            return f"[HTTP] {msg}"
        return msg


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    debug: bool = False
) -> logging.Logger:
    """Setup structured logging for the framework."""
    
    logger = logging.getLogger('sqlprobe')
    logger.setLevel(logging.DEBUG if debug else getattr(logging, level.upper()))
    
    logger.handlers.clear()
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if debug else getattr(logging, level.upper()))
    console_formatter = ColoredFormatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file, mode='a')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger


class RequestLogger:
    """Logger for HTTP requests and responses."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.trace_enabled = False
    
    def enable_tracing(self) -> None:
        """Enable request/response tracing."""
        self.trace_enabled = True
    
    def log_request(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        data: Optional[dict] = None
    ) -> None:
        """Log outgoing request."""
        if self.trace_enabled:
            self.logger.debug(f"Request: {method} {url}")
            if headers:
                self.logger.debug(f"  Headers: {headers}")
            if data:
                self.logger.debug(f"  Data: {data}")
    
    def log_response(
        self,
        status_code: int,
        url: str,
        headers: Optional[dict] = None,
        content_length: Optional[int] = None
    ) -> None:
        """Log incoming response."""
        if self.trace_enabled:
            self.logger.debug(f"Response: {status_code} from {url}")
            if content_length:
                self.logger.debug(f"  Content-Length: {content_length}")


class TrackedLogger:
    """Logger that tracks events for reporting."""
    
    def __init__(self):
        self.events: list = []
        self._start_time = datetime.now()
    
    def add_event(self, event_type: str, message: str, **kwargs) -> None:
        """Add a tracked event."""
        event = {
            'timestamp': datetime.now(),
            'type': event_type,
            'message': message,
            **kwargs
        }
        self.events.append(event)
    
    def get_events(self, event_type: Optional[str] = None) -> list:
        """Get events, optionally filtered by type."""
        if event_type:
            return [e for e in self.events if e['type'] == event_type]
        return self.events
    
    def clear(self) -> None:
        """Clear all events."""
        self.events.clear()
    
    def summary(self) -> dict:
        """Get summary of events."""
        event_counts = {}
        for event in self.events:
            event_type = event['type']
            event_counts[event_type] = event_counts.get(event_type, 0) + 1
        
        return {
            'total': len(self.events),
            'by_type': event_counts,
            'duration': (datetime.now() - self._start_time).total_seconds()
        }