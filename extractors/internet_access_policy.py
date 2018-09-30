from .base import AbstractExtractor, ResultCount
from bundle.bundle import Bundle

import os.path
import misc.filesystem as fs


class IAPExtractor(AbstractExtractor):
    """Extracts the Internet Access Policy of an application.

    The Internet Access Policy is a policy definition used by the popular
    Little Snitch tool to display information to users regarding domains
    used by the application. It has only been introduced recently and as such
    it is likely that usage thus far is very limited.

    If found, the file is stored as "iap.plist" inside the output directory.

    More information regarding this special file can be found on the website
    of Little Snitch's developer.

    According to https://help.obdev.at/littlesnitch/#/ra-developers,
    the Internet Access Policy is to be specified at the filepath below
    """

    @classmethod
    def resource_type(cls):
        # "iap" is short for internet access policy.
        return "iap"

    @classmethod
    def result_count(cls):
        return ResultCount.NONE_OR_SINGLE

    def extract_data(self, app: Bundle, result_path: str) -> bool:
        iap_path = app.path_for_resource("Contents/Resources/InternetAccessPolicy.plist")
        if not iap_path:
            self.log_info("IAP for application {} does not exist.".format(app.filepath))
            # This method _always_ returns True, because IAPs are optional and almost always
            # absent from applications
            return True
        else:
            self.log_info("IAP for application {} does exist.".format(app.filepath))
            fs.copy(iap_path, os.path.join(result_path, "iap.plist"))
            return True
