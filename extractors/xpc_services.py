"""Apple encourages developers to use XPC components for privilege-separation.
According to [1], XPC components are always located at Contents/XPCServices. They are therefore rather
easily scraped from apps.

Because Apple says XPC components are needed for both stability and privilege separation:
"In a sandboxed environment, you can further increase security with privilege separation—dividing
an application into smaller pieces that are responsible for a part of the application’s behavior.
This allows each piece to have a more restrictive sandbox than the application as a whole would require.

Other mechanisms for dividing an application into smaller parts, such as NSTask and posix_spawn,
do not let you put each part of the application in its own sandbox, so it is not possible to use
them to implement privilege separation. Each XPC service has its own sandbox, so XPC services
can make it easier to implement proper privilege separation." (see [1])

It is interesting to know just how many app developers are using XPC services, and how their
sandbox differs from the one of the main app

[1]: https://developer.apple.com/library/content/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html
"""

from .base import AbstractExtractor, ResultCount
from bundle.bundle import Bundle
from bundle.types import BundleType

import os
import os.path
import shutil


class XPCServicesExtractor(AbstractExtractor):
    """Extracts the XPC services of an application.

    The same information as for a normal application is extracted, meaning Info.plist and executable.
    This information is stored in one folder per XPC service. The extractors/executable.py and extractors/info.py
    extractors are re-used. Note that XPC services / dependencies inside of the XPC services themselves
    are not saved.

    Example resulting layout:
    result_path/
        com.xpc.service1/
            executable.bin
            info.plist
        com.xpc.service2/
            executable.bin
            info.plist
    """
    @classmethod
    def resource_type(cls):
        return "xpc_services"

    @classmethod
    def result_count(cls):
        return ResultCount.MULTIPLE

    def extract_data(self, app: Bundle, result_path: str) -> bool:
        from extractors.executable import ExecutableExtractor
        from extractors.info import InfoExtractor

        # Find all XPC bundles that are inside the overall application bundle
        for sub_bundle in app.sub_bundles():
            if not sub_bundle.bundle_type == BundleType.XPC_EXTENSION:
                continue

            # Create a new folder for the XPC bundle found previously.
            if not sub_bundle.has_bundle_identifier():
                self.log_error(
                    "{} found in {} @ {} does not have a bundle id.".format(
                        sub_bundle.bundle_type,
                        app.bundle_type,
                        app.filepath
                    )
                )
                # Abort on error
                return False

            # Create sub-directory for XPC bundles found.
            bundle_id = sub_bundle.bundle_identifier()
            xpc_result_path = os.path.join(result_path, bundle_id)
            os.mkdir(xpc_result_path)

            # Use ExecutableExtractor and InfoExtractor on the XPC bundle
            success = ExecutableExtractor().extract_data(sub_bundle, xpc_result_path)
            success &= InfoExtractor().extract_data(sub_bundle, xpc_result_path)

            # Abort immediately on failure. Overall extraction only works if every plugins could be extracted
            if not success:
                self.log_error(
                    "Data extraction failed for xpc plugin extraction from {} @ {}. Aborting.".format(
                        app.bundle_type,
                        app.filepath
                    )
                )

                # Cleanup: Delete directory
                shutil.rmtree(xpc_result_path)

                # Propagate errors
                return False

        return True
