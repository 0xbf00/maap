#!/usr/bin/env python3

import os
import logging
import json
import subprocess
import sys

from argparse import ArgumentParser
from termcolor import colored
from typing import Iterator

from appxtractor import folder_for_app, SignalIntelligence
from bundle.bundle import Bundle
from misc.logger import create_logger


def iterate_applications(directory: str) -> Iterator[str]:
    for root, dirs, files in os.walk(directory):
        if root.endswith('.app'):
            yield root

        app_candidates = [
            os.path.abspath(os.path.join(root, d))
            for d in dirs
            if d.endswith('.app')
        ]

        dirs[:] = [
            d
            for d in dirs
            if not d.endswith('.app')
        ]

        for candidate in app_candidates:
            yield candidate


def appnalyse(application_directory: str, root_output_directory: str, logger: logging.Logger) -> None:
    print("[    ] Analysing {}".format(application_directory))
    reset_cursor = "\r\033[1A["

    app = Bundle.make(application_directory)
    output_directory = folder_for_app(root_output_directory, app)

    output_fn = os.path.join(output_directory, 'appnalyse_results.json')

    # Skip application if we already obtained results
    if os.path.exists(output_fn):
        logger.warning("App already appnalysed: {}. Skipping.".format(application_directory))
        print(reset_cursor + colored("skip", 'yellow'))
        return

    # Run appnalyser for the given application
    cmd = [
        './appnalyser.py',
        application_directory,
    ]
    appnalyser = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        appnalyser.wait(60)
    except subprocess.TimeoutExpired:
        appnalyser.kill()
        logger.error("Timed out: {}".format(application_directory))
        print(reset_cursor + colored("err", 'red'))
        return

    stdout, stderr = appnalyser.communicate()

    if appnalyser.returncode != 0:
        logger.error(
            "appnalyser returned {} for {}: {}".format(
                appnalyser.returncode,
                application_directory,
                stderr.decode(),
            )
        )
        print(reset_cursor + colored("err ", 'red'))
        return

    try:
        json.loads(stdout.decode())
    except json.JSONDecodeError:
        logger.error(
            "appnalyzer did not produce JSON for {}: {}".format(
                application_directory,
                stdout.decode(),
            )
        )
        print(reset_cursor + colored("err ", 'red'))
        return

    # Store results
    os.makedirs(output_directory, exist_ok=True)
    with open(output_fn, 'wb') as fp:
        fp.write(stdout)

    print(reset_cursor + colored(" ok", 'green'))
    logger.info("Successfully appnalysed {}".format(application_directory))


def main() -> None:
    parser = ArgumentParser()

    parser.add_argument(
        'applications',
        help="Path to the directory, where applications are installed. This folder will be traversed recursively.",
    )
    parser.add_argument(
        'output',
        help="Path to where the results should be stored",
    )

    args = parser.parse_args()

    applications_directory = os.path.expanduser(args.applications)
    output_directory = os.path.expanduser(args.output)

    if not os.path.exists(applications_directory):
        print("Directory does not exist: {}".format(applications_directory), file=sys.stderr)
        exit(1)

    exit_watcher = SignalIntelligence()

    logger = create_logger('appnalyser_driver')

    logger.info("appnalyser_driver starting")

    for application_directory in iterate_applications(applications_directory):
        if exit_watcher.should_exit:
            break

        appnalyse(application_directory, output_directory, logger)

    logger.info("appnalyser_driver stopping")


if __name__ == '__main__':
    main()
