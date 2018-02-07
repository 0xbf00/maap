"""
appxtractor

(c) Jakob Rieck 2018

Tool to extract useful information from macOS .app bundles

What exactly is extracted is dependent on the extractors
defined in extractors/

Extractor classes need to implement the interface defined in
extractors/base.py.

Currently, the following data is saved for each version of each app:
    - The main executable
    - The main Info.plist
    - InternetAccessPolicy.plist, if available (this is a Little Snitch specific file)
    - a manifest containing information regarding each file that is part of the app bundle
    - executable and Info.plist for each XPC extension thats part of the bundle
    - Basic information (bundle id and version) for each dependency, where such information
      is available.

Results are stored in a simple folder structure at a location of the user's choosing. On every
run, each application is examined (though already processed versions are not re-processed). There
is no shared state, apart from the results folder.
"""

import os.path

from bundle.bundle import Bundle
import extractors.base
import shutil
import functools
from misc.logger import create_logger

import argparse
import signal


class SignalIntelligence:
    """A simple class to encapsulate reacting to signals (SIGINT, SIGTERM) and to exit the program
    gracefully in the event these signals are delivered."""
    should_exit = False

    def __init__(self):
        signal.signal(signal.SIGINT, self.process_signal)
        signal.signal(signal.SIGTERM, self.process_signal)

    def process_signal(self, signum, frame):
        self.should_exit = True


# ------------------
# Utility functions
def folder_for_app(results_dir : str, app : Bundle) -> str:
    """Return the output directory for a certain application
    inside the user-specified results directory.

    Note that this function _does not_ touch the filesystem.
    Therefore, no directories are created as part of this functionality"""
    app_bundle_id = app.bundle_identifier()
    app_version = None
    if "CFBundleShortVersionString" in app.info_dictionary():
        app_version = app.info_dictionary()["CFBundleShortVersionString"]
    elif "CFBundleVersion" in app.info_dictionary():
        app_version = app.info_dictionary()["CFBundleVersion"]

    if not app_version:
        return None

    return os.path.join(results_dir, app_bundle_id, app_version)


def run_extractor(extractor, app, app_result_path) -> bool:
    """Run a single extractor.

    If the extractor writes out more than a single result, create a dedicated
    directory for that directory. This directory is only retained if the extractor
    actually writes to it. In case no results are found there, the directory is removed
    again.

    Returns the status code of the extractor"""

    output_directory = app_result_path

    # Check whether we need to create another extra directory for the results
    # and create the directory, if needed (when there might be multiple results)
    if extractor.result_count() == extractors.base.ResultCount.MULTIPLE:
        output_directory = os.path.join(app_result_path, extractor.resource_type())
        os.mkdir(output_directory)

    status_code = extractor.extract_data(app, output_directory)

    # Verify that the program used the output directory, in case MULTIPLE results where possible.
    # Otherwise, delete the output directory
    if extractor.result_count() == extractors.base.ResultCount.MULTIPLE:
        output_contents = os.listdir(output_directory)
        if output_contents == []:
            shutil.rmtree(output_directory)
        # Make sure we also remove the directory if only a temporary file exists there.
        elif len(output_contents) == 1 and output_contents[0] == ".DS_Store":
            shutil.rmtree(output_directory)

    return status_code


def process_app(app_path, info_extractors, logger, output):
    """Process an app using the supplied `info_extractors`

    Log potentially relevant information to `logger` and return results
    at `output`
    """

    app = Bundle.make(app_path)

    output_folder = folder_for_app(output, app)
    if os.path.exists(output_folder):
        logger.info(
            "Skipping processing of {} @ {}, because the app has already been processed.".format(app, app.filepath)
        )
        return

    # Make basefolder
    os.makedirs(output_folder)

    try:
        extraction_status = functools.reduce(
            lambda status, extractor: status & run_extractor(extractor, app, output_folder),
            info_extractors,
            True
        )
        if not extraction_status:
            logger.info("Processing failed for {} @ {}".format(app, app.filepath))
    except:
        logger.error(
            "Exception occurred during processing of {} @ {}".format(app, app.filepath)
        )


def main():
    logger = create_logger('appxtractor')
    logger.info("appxtractor starting")

    parser = argparse.ArgumentParser(description='Extract information from Mac Apps.')
    parser.add_argument('-i', '--input', required=True,
                        help='The directory that contains the applications to analyse.')
    parser.add_argument('-o', '--output', required=True,
                        help='Output directory: This directory shall also be passed to this program to update an existing output folder.')
    parser.add_argument('--all-apps', dest='all_apps', default=False, action='store_true',
                        help='Analyse all apps. By default, only Mac AppStore apps are analysed.')

    args = parser.parse_args()

    # Instantiate the extractors once
    info_extractors = [cls() for cls in extractors.base.all_extractors()]

    exit_watcher = SignalIntelligence()


    print("[+] Analysing apps at \"{}\"".format(args.input))

    all_apps = []

    for app_path in os.listdir(args.input):
        full_path = os.path.join(args.input, app_path)
        if app_path.endswith(".app") and Bundle.is_bundle(full_path):
            bundle = Bundle.make(full_path)
            if args.all_apps:
                all_apps.append(full_path)
            elif bundle.is_mas_app():
                all_apps.append(full_path)

    print("[+] Found {} apps to analyse.".format(len(all_apps)))
    print("\n[+] Press Ctrl+C to cancel analysis (can later be resumed)")

    for (index, app_path) in enumerate(all_apps):
        # Print crude progress bar
        if exit_watcher.should_exit:
            break

        print('\r[+] Progress: {:0>5d}/{:0>5d} apps done -- {:2.4f}%'.format(index+1,
                                                                             len(all_apps),
                                                                             ((index+1) / len(all_apps)) * 100),
              end='')

        process_app(app_path=app_path,
                    info_extractors=info_extractors,
                    logger=logger,
                    output=args.output)

    logger.info("appxtractor stopping")


if __name__ == "__main__":
    main()