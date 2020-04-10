"""Logging, because almost all loggers look the same."""

import logging
import os
from .filesystem import project_path

LOGGING_DIRECTORY = project_path("logs/")
if not os.path.exists(LOGGING_DIRECTORY):
    os.mkdir(LOGGING_DIRECTORY)


def create_logger(logger_name, level=logging.INFO):
    """
    Create a logger with the specified name, logging into a central
    logging directory.
    :param logger_name: The name of the logger.
    :param level: The log level. Defaults to logging.INFO.
    :return: Logger object
    """
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)

    # Log events to file
    # We do not log anything to the console, because there is no
    # user present during execution who could benefit from
    # such messages. Logs are purely needed for examining defects
    # after the fact.
    fh = logging.FileHandler(
        os.path.join(LOGGING_DIRECTORY, "{}.log".format(logger_name))
    )
    fh.setLevel(logging.INFO)

    # Custom formatter for log messages
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    return logger
