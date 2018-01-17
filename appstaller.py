"""
appstaller

(c) Jakob Rieck 2018

Tool to install (and purchase) apps from the MAS, in an automatic fashion
"""

import json
import requests
import time
import argparse

from os import popen

from misc.logger import create_logger

logger = create_logger('appstaller')


class MacApp:
    """The MacApp class wraps common operations such as getting the
    current price."""

    def __init__(self, itemID: str):
        self.itemID = itemID

    def get_price(self) -> float:
        """getPrice() uses the iTunes API to retrieve the current price
        of the app. Right now, the german store is hardcoded, although this
        can easily be replaced."""

        itunes_url = 'https://itunes.apple.com/de/lookup?id={}'.format(self.itemID)
        response = requests.get(itunes_url)
        if response.status_code == 200:
            obj = json.loads(response.content.decode('utf-8'))
            if obj["resultCount"] >= 1:
                app_info = obj["results"][0]
                if "price" in app_info:
                    return app_info["price"]
                else:
                    logger.info("API response does not contain price attribute. Skipping.")
            else:
                logger.info("No results for API request. Skipping.")

        return -1.0


def install_app(item_id: str, is_update = False, force_install = False) -> bool:
    logger.info("Attempting to install {}. (As update? {})".format(item_id, is_update))

    command_str = "mas purchase " if not is_update else "mas install "

    cmd_handle = popen("%s%s" % (command_str, item_id))
    mas_log = cmd_handle.read()
    cmd_handle.close()

    logger.info(mas_log)


def main():
    parser = argparse.ArgumentParser(description='Download apps from the Mac App Store.')
    parser.add_argument('--apps', required=True,
                        help='Textfile containing trackId of apps to download (one per line)')
    parser.add_argument('--force', dest='force_install', default=False, action='store_true',
                        help='Install apps even if that app is already installed')
    args = parser.parse_args()

    successes = []

    with open(args.apps) as input:
        for trackId in input:
            trackId = trackId.strip()
            itunes_info = MacApp(trackId)
            current_price = itunes_info.get_price()
            if current_price == 0.0:
                # Attempt to install free app
                success = install_app(trackId, force_install=args.force)
                if not success:
                    logger.info("Unable to install app with trackId {}".format(trackId))

                successes.append(success)
                if len(successes) >= 5 and not any(successes[-5:]):
                    logger.error("Failed to install apps for five consecutive times. Stopping.")
                    break
                time.sleep(5)


if __name__ == "__main__":
    main()