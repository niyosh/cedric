import logging
import os
import sys


def setup_logger(level="INFO"):

    os.makedirs("logs", exist_ok=True)

    logger = logging.getLogger("AsyncScanner")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # --------------------------------------------------
    # FILE HANDLER (UTF-8 SAFE)
    # --------------------------------------------------
    file_handler = logging.FileHandler(
        "logs/scan.log",
        encoding="utf-8"
    )
    file_handler.setFormatter(formatter)

    # --------------------------------------------------
    # CONSOLE HANDLER (UTF-8 SAFE FOR WINDOWS)
    # --------------------------------------------------
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    # Prevent duplicate handlers
    if not logger.handlers:
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger