#!/usr/bin/env python3

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

import os
import shutil
import functools
import argparse
import signal
import sys
import tempfile

from termcolor import colored

import extractors.base

from bundle.bundle import Bundle
from misc.logger import create_logger
from misc.archives import extract_zip, extract_tar, extract_gzip
import misc.dmglib as dmglib


logger = create_logger('appxtractor')
# Instantiate the extractors once
info_extractors = [ cls() for cls in extractors.base.all_extractors() ]


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
    if app_bundle_id is '' or app_bundle_id is None:
        app_bundle_id = 'b.UNKNOWN'

    app_version = app.version()
    if app_version is '' or app_version is None:
        app_version = 'v.UNKNOWN'

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


def process_app(app_path, info_extractors, logger, output, source_hint: str=None):
    """Process an app using the supplied `info_extractors`

    Log potentially relevant information to `logger` and return results
    at `output`. If supplied, the `source_hint` will be written to
    `output/source`
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
        # The source_hint can for example be used to store an application's identifier for
        # the third-party platform where the app was downloaded from (i.e macupdate)
        if source_hint is not None:
            with open(os.path.join(output_folder, 'source'), 'w') as source_file:
                source_file.write(source_hint)

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


def install_app(app_path: str, logger, output: str):
    """Install an app from the `app_path` into the `output` directory."""

    app = Bundle.make(app_path)
    output_folder = os.path.join(folder_for_app(output, app), os.path.basename(app_path))

    try:
        shutil.copytree(app_path, output_folder, symlinks=True)
    except FileExistsError:
        logger.error("Application already exists: {}. Skipping.".format(output_folder))
        print('\r[' + colored('skip', 'yellow'))
        return

    logger.info("Installed application: {}".format(output_folder))
    print('\r[' + colored(' ok ', 'green'))


def iterate_apps_folder(input, source_hint=None):
    """
    Iterate all .app bundles in the specified folder.
    Returns pairs of .app bundle path, source_hint
    """
    for root, dirs, files in os.walk(input):
        if root.endswith('.app'):
            yield root, source_hint

        app_candidates = [ os.path.abspath(os.path.join(root, d))
            for d in dirs
            if d.endswith('.app') ]

        # Do not recurse further down into app bundles
        dirs[:] = [ d 
            for d in dirs 
            if not d.endswith('.app') ]

        for candidate in app_candidates:
            yield candidate, source_hint


def iterate_archived_apps_folder(input, source_hint=None):
    """
    Process all archives: Check for included .app bundles.
    Returns pairs of .app bundle path, source_hint
    """
    for root, dirs, files in os.walk(input):
        for f in files:
            filepath = os.path.join(root, f)

            # Try to mount as dmg
            if      dmglib.DiskImage.is_valid(filepath) and\
                not dmglib.DiskImage.is_encrypted(filepath):
                try:
                    with dmglib.attachedDiskImage(filepath) as mount_points:
                        for point in mount_points:
                            yield from iterate_apps_folder(point, 
                                source_hint=source_hint or f)
                except dmglib.AttachingFailed:
                    # This is a dmg file, but could not be attached (e.g. because of
                    # license agreement dialog)
                    continue
            else:
                # Try to mount this as one of the support archive formats
                with tempfile.TemporaryDirectory() as tempdir:
                    success = extract_zip(filepath, tempdir) or\
                              extract_tar(filepath, tempdir)

                    if success:
                        yield from iterate_apps_folder(tempdir, source_hint=source_hint or f)
                    else:
                        success, _ = extract_gzip(filepath, tempdir)
                        if success:
                            yield from iterate_archived_apps_folder(tempdir, 
                                source_hint=source_hint or f)
                        else:
                            logger.error('Could not process archive / image at {}'.format(filepath))


def main():
    logger.info("appxtractor starting")

    parser = argparse.ArgumentParser(description='Extract information from Mac Apps.')
    parser.add_argument('-i', '--input', required=True,
                        help='The directory that contains the applications to analyse.')
    parser.add_argument('-t', '--type', 
                        default='app_folder', const='app_folder', 
                        nargs='?', choices=['app_folder', 'archive_folder'],
                        help='''Process input folder as folder containing .app bundles
                                or as folder full of archives containing .app bundles.
                                Supported archives formats are zip, tar, gz and dmg. 
                                Default type: app_folder''')
    parser.add_argument('-o', '--output', required=True,
                        help='Output directory: This directory shall also be passed to this program to update an existing output folder.')
    parser.add_argument('--all-apps', dest='all_apps', default=False, action='store_true',
                        help='Analyse all apps. By default, only Mac AppStore apps are analysed.')
    parser.add_argument('--install-only', default=False, action='store_true',
                        help='''Install archived applications into the output directory.
                                This option only works with archive folders.''')

    args = parser.parse_args()

    if args.type != 'archive_folder' and args.install_only:
        print("Option '--install-only' is only supported for archive folders.", file=sys.stderr)
        exit(1)

    exit_watcher = SignalIntelligence()

    if args.install_only:
        print("[+] Installing apps from \"{}\" to \"{}\"".format(args.input, args.output))
        print("[+] Press Ctrl+C to cancel installation\n")
    else:
        print("[+] Analysing apps at \"{}\"".format(args.input))
        print("[+] Press Ctrl+C to cancel analysis (can later be resumed)\n")

    if args.type == 'app_folder':
        app_candidates = iterate_apps_folder(args.input)
    elif args.type == 'archive_folder':
        app_candidates = iterate_archived_apps_folder(args.input)
    else:
        assert False and 'Iteration type not supported.'

    for path, hint in app_candidates:
        if exit_watcher.should_exit:
            break

        if not Bundle.is_bundle(path):
            continue

        bundle = Bundle.make(path)
        if not bundle.is_mas_app() and not args.all_apps and not args.install_only:
            continue

        if args.install_only:
            print('[    ] Installing {}'.format(path), end='')
            install_app(app_path=path,
                        logger=logger,
                        output=args.output)
        else:
            print('[+] Processing {}'.format(path))
            process_app(app_path=path,
                        info_extractors=info_extractors,
                        logger=logger,
                        output=args.output,
                        source_hint=hint)

    logger.info("appxtractor stopping")


if __name__ == "__main__":
    main()
