"""
Logging system for PrivGuard
"""

import logging
import os
from datetime import datetime
from pathlib import Path
import config

def setup_logger(name: str = "PrivGuard", log_file: str = None) -> logging.Logger:
    """
    Set up and configure logger
    
    Args:
        name: Logger name
        log_file: Optional log file path
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, config.LOG_LEVEL))
    
    # Prevent duplicate handlers
    if logger.handlers:
        return logger
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_format = logging.Formatter(config.LOG_FORMAT)
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)
    
    # File handler
    if log_file is None:
        log_file = config.LOGS_DIR / f"privguard_{datetime.now().strftime('%Y%m%d')}.log"
    
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(config.LOG_FORMAT)
    file_handler.setFormatter(file_format)
    logger.addHandler(file_handler)
    
    return logger

# Global logger instance
logger = setup_logger()
