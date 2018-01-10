"""
Support class for Plugin infrastructure. `Extractor` is the base class of
every plugin in the system.
"""
from bundle.bundle import Bundle

import logging

import abc
from enum import Enum, auto


class ResultCount(Enum):
    NONE_OR_SINGLE = auto()
    SINGLE         = auto()
    MULTIPLE       = auto()


def create_module_logger():
    logger = logging.getLogger('extractor')
    logger.setLevel(logging.INFO)
    # Log events to file
    # We do not log anything to the console, because there is no
    # user present during execution who could benefit from
    # such messages. Logs are purely needed for examining defects
    # after the fact.
    fh = logging.FileHandler("logs/extractor.log")
    fh.setLevel(logging.INFO)
    # Custom formatter for log messages
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    return logger


# This top level logger is not used at all. Its settings (formatting, output file, ...)
# are used by lower-level loggers (those used in the individual classes)
module_logger = create_module_logger()


class AbstractExtractor(abc.ABC):
    """Abstract base class for the plugin infrastructure"""
    def __init__(self):
        self.logger = logging.getLogger("extractor.{}".format(self.__class__.resource_type()))

    @classmethod
    @abc.abstractmethod
    def resource_type(cls):
        """The type of resource extracted by the particular resource.
        This should be a single word only -- meaning something like "info", "executable", ...
        This resource type is used for better log messages."""
        pass

    @classmethod
    @abc.abstractmethod
    def result_count(cls) -> ResultCount:
        """The number of results a plug-in aims to place on the filesystem.

        The exact number does not matter: Instead, a plugin should return either
        ResultCount.SINGLE or ResultCount.MULTIPLE, indicating that they intend to
        store a single file (1) or multiple files (> 1).

        For plugins where the number of files extracted depends on the input data,
        return ResultCount.MULTIPLE (or NONE_OR_SINGLE, if either 0 or 1 is extracted)
        """
        pass

    def log_error(self, msg):
        """Log any errors that occur. Errors are conditions that are unusual and are
        not occurring often.
        One example for this would be that an application has no executable."""
        self.logger.error(msg)

    def log_info(self, msg):
        """Log info messages to be able to mentally understand what happened during
        program execution"""
        self.logger.info(msg)

    @abc.abstractmethod
    def extract_data(self, app : Bundle, result_path : str) -> bool:
        """Extract data / files from the application `app`.

        A extractor should put these files at `result_path` and log any errors to `logger`.
        The return code should be `True` on success, `False` otherwise. """
        pass


def all_extractors():
    """Returns a list of all extractor classes"""

    import os.path
    import importlib
    import inspect

    extractors = []

    # Rudimentary parsing of the directory to find all python files
    plugin_dir = os.path.dirname(__file__)
    # Assuming the plugins are all stored in the extractors/ dir where also
    # the base class is stored.
    for filename in os.listdir(plugin_dir):
        if filename == "base.py":
            continue

        if filename.endswith(".py"):
            module = importlib.import_module("extractors.{}".format(
                os.path.splitext(filename)[0]
            ))
            classes = inspect.getmembers(module, lambda x: inspect.isclass(x))
            for cls_name, cls in classes:
                if not issubclass(cls, AbstractExtractor):
                    continue

                if cls == AbstractExtractor:
                    continue
                extractors.append(cls)

    return extractors
