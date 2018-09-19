from .base import AbstractExtractor, ResultCount
from bundle.bundle import Bundle

import os.path
import shutil


class InfoExtractor(AbstractExtractor):
    """Extracts the Info.plist of an application

    This extractor simply copies the Info.plist file from the application
    to the output folder."""
    @classmethod
    def resource_type(cls):
        return "info"

    @classmethod
    def result_count(cls):
        return ResultCount.SINGLE

    def extract_data(self, app: Bundle, result_path: str) -> bool:
        info_path = app.info_dictionary_path()
        if not os.path.exists(info_path):
            self.log_error("Info.plist for {} {} could not be found.".format(app.bundle_type, app.filepath))
            return False

        shutil.copy2(info_path, os.path.join(result_path, "Info.plist"))
        return True
