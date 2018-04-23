from extractors.base import AbstractExtractor, ResultCount
from bundle.bundle import Bundle

import os
import json

import misc.itunes_api as itunes_api


class MetadataExtractor(AbstractExtractor):
    """Extracts and stores the iTunes metadata of an application"""
    @classmethod
    def resource_type(cls):
        return 'metadata'

    @classmethod
    def result_count(cls):
        return ResultCount.NONE_OR_SINGLE

    def extract_data(self, app: Bundle, result_path: str) -> bool:
        app_bundle_id = app.bundle_identifier()
        metadata = itunes_api.lookup_metadata(bundleId=app_bundle_id)
        if not metadata:
            self.log_info('Metadata could not be extracted for {}'.format(app.filepath))
            return True

        outpath = os.path.join(result_path, 'itunes_metadata.json')
        with open(outpath, "w") as outfile:
            json.dump(metadata, outfile, indent=4)

        return True
