import logging
import os
from logging.handlers import RotatingFileHandler


def setup_logging(log_file: str, level: int = logging.INFO) -> logging.Logger:
    """
    Configure and return a logger for the pentest framework.

    - Ensures the log directory exists
    - Adds a rotating file handler
    - Adds a console (stream) handler
    """
    # Ensure log directory exists
    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger("pentest")
    logger.setLevel(level)

    # Prevent adding multiple handlers if called multiple times
    if logger.handlers:
        return logger

    # Log message format
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s [%(name)s] %(message)s"
    )

    # Rotating file handler: 5MB per file, keep 5 backups
    file_handler = RotatingFileHandler(
        log_file, maxBytes=5 * 1024, backupCount=5
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Console handler for stdout
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger
