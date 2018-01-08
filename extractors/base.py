"""
Support class for Plugin infrastructure. `Extractor` is the base class of
every plugin in the system.
"""
from bundle.application import Application

import abc
from enum import Enum, auto


class ResultCount(Enum):
    NONE_OR_SINGLE = auto()
    SINGLE         = auto()
    MULTIPLE       = auto()


class Extractor(abc.ABC):
    """Abstract base class for the plugin infrastructure"""

    @classmethod
    def extractor_name(cls):
        return cls.__name__

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

    @classmethod
    @abc.abstractmethod
    def extract_data(cls, app : Application, result_path : str, logger) -> bool:
        """Extract data / files from the application `app`.

        A extractor should put these files at `result_path` and log any errors to `logger`.
        The return code should be `True` on success, `False` otherwise. """
        pass
