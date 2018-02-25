"""
appintel

(c) Jakob Rieck 2018

Tool to collect sandbox logs for a given application. Sandbox logs contain
all allow and deny decisions that sandboxd was nice enough to log to the system log.
"""
import argparse
import os
import subprocess
import tempfile
import datetime

from misc.logger import create_logger
from bundle.bundle import Bundle

logger = create_logger('appintel')

# TODO Make sure this works without absolute paths!

def main():
    parser = argparse.ArgumentParser(description='Collect sandbox logs for an application run')
    parser.add_argument('--app', required=True,
                        help='Path to the app for which to collect sandbox logs.')
    parser.add_argument('--outfile', required=True,
                        help='Location where to store the logfiles at.')
    args = parser.parse_args()

    app_path = args.app
    if not (app_path.endswith(".app") or app_path.endswith(".app/")) and Bundle.is_bundle(app_path):
        logger.error("Provided path {} is not a valid app. Skipping.".format(app_path))
        return

    bundle = Bundle.make(app_path)

    app_bin = bundle.executable_path()

    # In order to patch and re-generate the sandbox profile used by an application,
    # we needs its Container metdata, which is generated during profile generation.
    # As such, we first start the app, let the sandbox do its job, then exit.
    # Thankfully, Apple provides an environment variable that does just that.
    init_sandbox_environ = {**os.environ, 'APP_SANDBOX_EXIT_AFTER_INIT': str(1)}

    logger.info("Starting process {} to initialize sandbox.".format(bundle.executable_path()))

    subprocess.call(bundle.executable_path(), env=init_sandbox_environ)

    with tempfile.TemporaryDirectory() as tempdir:
        # Use the existing interpreter to create a new sandbox profile
        # that logs every operation (all allowed ones) to the syslog
        profile_file = open(os.path.join(tempdir, "patched_profile.sb"), "wb")
        sbpl = ["/Users/jakobrieck/msc-thesis/sbpl/build/sbpl", "--scheme", "--patch",
                "--bundle-id", bundle.bundle_identifier(),
                "--profile", "/Users/jakobrieck/Desktop/application_1.sb"]
        subprocess.call(sbpl, stdout = profile_file, cwd = "/Users/jakobrieck/msc-thesis/sbpl")
        profile_file.close()

        # Record starting time
        start = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Insert a patched libsystem_secinit into the program.
        # Libsystem_secinit is responsible for initializing the sandbox.
        # By specifying a custom profile using the environment variable "PATCHED_SB_PROFILE",
        # our profile is loaded instead of the usual profile.
        logging_environ = {
            **os.environ,
            # TODO Make relative path
            'DYLD_INSERT_LIBRARIES': "/Users/jakobrieck/Programming/sandboxctl/lib/libsystem_secinit.dylib",
            'PATCHED_SB_PROFILE': os.path.join(tempdir, "patched_profile.sb")
        }

        logger.info("Starting process {} to collect sandbox logs.".format(bundle.executable_path()))

        # TODO: Make sure our library is loaded.
        log_sbpl = ["DYLD_INSERT_LIBRARIES=/Users/jakobrieck/Programming/sandboxctl/lib/libsystem_secinit.dylib",
                         "PATCHED_SB_PROFILE=" + os.path.join(tempdir, "patched_profile.sb"),
                         bundle.executable_path()]
        print(log_sbpl)
        subprocess.Popen()
        subprocess.call(log_sbpl, env=logging_environ, shell = True)

        end = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        outfile = open(args.outfile, "wb")

        # Collect logs and store them at the output location
        subprocess.call(["log", "show",
                         "--start", start,
                         "--end", end,
                         "--style", "json"],
                         # "--predicate", 'senderImagePath == "/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox"'],
                        stdout = outfile)


if __name__ == "__main__":
    main()