#!/usr/bin/env python3

import argparse
import os
import json
import subprocess

import driver
from bundle.bundle import Bundle


class AppnalyseDriver(driver.Driver):

    def __init__(self) -> None:
        super().__init__('appnalyser_driver')

    def analyse(self, app: Bundle, out_dir: str) -> driver.Result:
        out_fn = os.path.join(out_dir, 'appnalyse.json')

        # Skip application if we already obtained results
        if os.path.exists(out_fn):
            self.logger.warning(f"App already appnalysed: {app.filepath}. Skipping.")
            return driver.Result.SKIPPED

        # Run appnalyser for the given application
        try:
            subprocess.run
            appnalyser = subprocess.run(
                ['./appnalyser.py', app.filepath],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            self.logger.error(f"Timed out: {app.filepath}")
            return driver.Result.ERROR

        if appnalyser.returncode != 0:
            self.logger.error(
                "appnalyser returned {} for {}: {}".format(
                    appnalyser.returncode,
                    app.filepath,
                    appnalyser.stderr,
                )
            )
            return driver.Result.ERROR

        try:
            json.loads(appnalyser.stdout)
        except json.JSONDecodeError:
            self.logger.error(
                f"appnalyzer did not produce valid JSON for {app.filepath}: {appnalyser.stdout}"
            )
            return driver.Result.ERROR

        # Store results
        os.makedirs(out_dir, exist_ok=True)
        with open(out_fn, 'w') as fp:
            fp.write(appnalyser.stdout)

        self.logger.info(f"Successfully appnalysed {app.filepath}")
        return driver.Result.OK


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        'applications',
        help="""
            Path to the directory, where applications are installed. This
            folder will be traversed recursively.
        """,
    )
    parser.add_argument(
        'output',
        help="Path to where the results should be stored",
    )

    args = parser.parse_args()

    apps_dir = os.path.expanduser(args.applications)
    out_dir = os.path.expanduser(args.output)

    driver = AppnalyseDriver()
    driver.run(apps_dir, out_dir)


if __name__ == '__main__':
    main()
