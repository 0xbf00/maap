#! /usr/bin/env python3

"""
appstaller

(c) Jakob Rieck 2018

Tool to install (and purchase) apps from the MAS, in an automatic fashion
"""

import time
import argparse
import enum

from os import popen

from misc.logger import create_logger
from misc.os_support import os_is_compatible
import misc.itunes_api as itunes_api

logger = create_logger('appstaller')


class Operation(str, enum.Enum):
    PURCHASE = "purchase"
    INSTALL = "install"
    UPGRADE = "upgrade"

    def __str__(self) -> str:
        return self.value


class MacApp:
    """
    The MacApp class wraps common operations such as getting the
    current price.
    """
    def __init__(self, itemID: str):
        self.itemID = itemID
        # Cache the response so that during app extraction we do not need to query
        # the iTunes API again.
        self.api_result = itunes_api.lookup_metadata(trackId = itemID,
                                                     cache = True)
        if self.api_result is None:
            logger.error('Failed to lookup itunes metadata for {}'.format(itemID))

    def get_price(self) -> float:
        """get_price() uses the iTunes API to retrieve the current price
        of the app. Right now, the german store is hardcoded, although this
        can easily be replaced."""
        if self.api_result is None:
            return -1.0

        return self.api_result.get('price', -1.0)

    def min_version(self):
        if self.api_result is None:
            return None

        return self.api_result.get('minimumOsVersion')


def install_app(item_id: str, operation: Operation) -> bool:
    logger.info(f"Attempting to {operation} {item_id}.")

    command_str = f"mas {operation} {item_id}"

    cmd_handle = popen(command_str)
    mas_log = cmd_handle.read()
    cmd_handle.close()

    logger.info(mas_log)

    if operation == Operation.PURCHASE and 'has already been purchased' in mas_log:
        return install_app(item_id, Operation.INSTALL)

    return "Installed" in mas_log


def main():
    parser = argparse.ArgumentParser(description='Download apps from the Mac App Store.')
    parser.add_argument('--new-apps', required=True,
                        help='Textfile containing trackId of apps to purchase (one per line)')
    parser.add_argument('--updates', required=True,
                        help='Textfile containing trackId of apps for which to download an update (one per line)')
    args = parser.parse_args()

    successes = []

    logger.info("Installing newly released apps.")
    with open(args.new_apps) as input:
        for trackId in input:
            trackId = trackId.strip()
            if trackId == "":
                continue

            itunes_info = MacApp(trackId)
            current_price = itunes_info.get_price()
            min_version_required = itunes_info.min_version()

            if current_price == 0.0 and min_version_required and os_is_compatible(min_version_required):
                # Attempt to purchase free app
                success = install_app(trackId, Operation.PURCHASE)
                if not success:
                    logger.info("Unable to install app with trackId {}".format(trackId))

                successes.append(success)
                if len(successes) >= 5 and not any(successes[-5:]):
                    logger.error("Failed to install apps for five consecutive times. Stopping.")
                    break
            time.sleep(5)

    logger.info("Installing and downloading updates.")
    with open(args.updates) as input:
        for trackId in input:
            trackId = trackId.strip()
            if trackId == "":
                continue

            itunes_info = MacApp(trackId)
            current_price = itunes_info.get_price()
            min_version_required = itunes_info.min_version()

            if current_price == 0.0 and min_version_required and not min_version_required.startswith('10.13'):
                # Attempt to install update for previously purchased free app
                success = install_app(trackId, Operation.UPGRADE)
                if not success:
                    logger.info("Unable to install app with trackId {}".format(trackId))

                successes.append(success)
                if len(successes) >= 5 and not any(successes[-5:]):
                    logger.error("Failed to install apps for five consecutive times. Stopping.")
                    break
                time.sleep(5)


if __name__ == "__main__":
    main()
