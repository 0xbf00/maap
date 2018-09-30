from .base import AbstractExtractor, ResultCount
from bundle.bundle import Bundle

import os.path
import misc.filesystem as fs


class ExecutableExtractor(AbstractExtractor):
    """Extracts the executable of an application

    This extractor stores the result as \"executable.bin\" in the folder
    supplied by the caller, disregarding the original filename. This
    ensures that all executables have the same name and are therefore
    easier to deal with later on. Further more, the original executable name
    can be restored simply by consulting the original Info.plist (see also: extractors/info.py)"""
    @classmethod
    def resource_type(cls):
        return "executable"

    @classmethod
    def result_count(cls):
        return ResultCount.SINGLE

    def extract_data(self, app: Bundle, result_path: str) -> bool:
        executable_path = app.executable_path()
        if not os.path.exists(executable_path):
            self.log_error("Executable for {} {} could not be found.".format(app.bundle_type, app.filepath))
            return False

        fs.copy(executable_path, os.path.join(result_path, "executable.bin"))
        return True
