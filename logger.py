"""
logger.py

Provides structured logging for the Wi-Fi Traffic Analyzer.
Supports log rotation, multiple log levels, and error handling.
Easy integration with all modules for consistent, secure logging.
"""

import logging
from logging.handlers import RotatingFileHandler
from typing import Optional
import os

DEFAULT_LOG_CONFIG = {
    "log_file": "analyzer.log",
    "max_bytes": 5 * 1024 * 1024,  # 5 MB
    "backup_count": 3,
    "level": "INFO",
    "console": True
}

class LoggerManager:
    """
    Sets up and manages structured logging with rotation and error handling.
    Use get_logger() to retrieve a configured logger for any module.
    """
    def __init__(self, config: Optional[dict] = None):
        self.config = DEFAULT_LOG_CONFIG.copy()
        if config:
            self.config.update(config)
        self.log_file = self.config["log_file"]
        self.max_bytes = self.config["max_bytes"]
        self.backup_count = self.config["backup_count"]
        self.level = getattr(logging, self.config["level"].upper(), logging.INFO)
        self.console = self.config["console"]
        self.logger = None
        self._setup_logger()

    def _setup_logger(self):
        logger = logging.getLogger("AnalyzerLogger")
        logger.setLevel(self.level)
        logger.handlers.clear()
        formatter = logging.Formatter(
            fmt='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        # File handler with rotation
        file_handler = RotatingFileHandler(
            self.log_file, maxBytes=self.max_bytes, backupCount=self.backup_count
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        # Console handler
        if self.console:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
        self.logger = logger

    def get_logger(self, name: Optional[str] = None) -> logging.Logger:
        """
        Return a logger instance for the given module name.
        """
        if name:
            return self.logger.getChild(name)
        return self.logger

    def set_level(self, level: str):
        """
        Dynamically set the logging level.
        """
        self.level = getattr(logging, level.upper(), logging.INFO)
        self.logger.setLevel(self.level)

if __name__ == "__main__":
    # Example usage and test
    log_config = {
        "log_file": "test.log",
        "max_bytes": 1024 * 1024,
        "backup_count": 2,
        "level": "DEBUG",
        "console": True
    }
    logger_mgr = LoggerManager(log_config)
    logger = logger_mgr.get_logger("TestModule")
    logger.debug("Debug message")
    logger.info("Info message")
    logger.warning("Warning message")
    logger.error("Error message")
    logger.critical("Critical message")
    logger_mgr.set_level("ERROR")
    logger.info("This info message should not appear after level set to ERROR.")
