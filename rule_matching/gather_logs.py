"""
gather_logs

(c) Jakob Rieck 2018

Tool to collect sandbox logs for a given application. Sandbox logs contain
all allow and deny decisions that sandboxd was nice enough to log to the system log.
"""
import argparse
import os
import subprocess
import datetime

from misc.logger import create_logger
from bundle.bundle import Bundle

ROOT_DIR = "/Users/jakobrieck/msc-thesis"

logger = create_logger('appintel')

def mk_absolute(path):
    return os.path.join(ROOT_DIR, path)

def main():
    parser = argparse.ArgumentParser(description='Collect sandbox logs for an application run')
    parser.add_argument('--app', required=True,
                        help='Path to the app for which to collect sandbox logs.')
    parser.add_argument('--outdir', required=True,
                        help='Location where to store logfiles and sandbox profiles at.')
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

    if os.path.isdir(args.outdir):
        print("Cannot use {}, as the folder already exists.".format(args.outdir))
        return

    outdir = args.outdir
    os.mkdir(args.outdir)

    # Use the existing interpreter to create a new sandbox profile
    # that logs every operation (all allowed ones) to the syslog
    sbpl = [mk_absolute("sbpl/build/sbpl"), "--scheme", "--patch",
            "--bundle-id", bundle.bundle_identifier(),
            "--profile", mk_absolute("sbpl/application.sb"),
            "--output", os.path.join(outdir, "patched_profile.sb")]

    subprocess.call(sbpl, cwd = mk_absolute("sbpl"))

    # Compile the profile using stefan esser's tool
    subprocess.call([mk_absolute("testing/compile_sb"),
                     os.path.join(outdir, "patched_profile.sb"),
                     os.path.join(outdir, "patched_profile.bin")])

    # The easiest way to make sure our patched profile is actually used would be
    # to hook the responsible methods in libsystem_secinit and make them load another
    # profile at runtime. Unfortunately, stock macOS kernels set the CS_RESTRICT flag on
    # applications that have entitlements and dyld will ignore all DYLD_ variables,
    # making this impossible without patching the kernel. (or patching dyld, but dyld is a
    # platform binary which further complicates this task)
    # However, one can simply modify the Container.plist metadata file. Simply modify the
    # SandboxProfileData embedded and the sandbox will happily use this profile.

    # Replace the sandbox profile data with our custom compiled profile (see above)
    # PlistBuddy is a useful program to do this.
    container_metadata = os.path.join(os.path.expanduser("~/Library/Containers"), bundle.bundle_identifier(), "Container.plist")
    assert os.path.isfile(container_metadata)

    subprocess.call([
        "/usr/libexec/PlistBuddy",
        "-c", "Import SandboxProfileData \"{}\"".format(os.path.join(outdir, "patched_profile.bin")),
        container_metadata
    ])

    # Record starting time
    start = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    logger.info("Starting process {} to collect sandbox logs.".format(bundle.executable_path()))


    process = subprocess.Popen([bundle.executable_path()])

    # Record PID to file, because we need it to filter needed log entries.
    with open(os.path.join(outdir, "process.pid"), "w") as pid_file:
        print("{}".format(process.pid), file = pid_file)

    # Let the process run for 60 seconds.
    try:
        process.wait(60)
    except subprocess.TimeoutExpired:
        process.terminate()

    end = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    outfile = open(os.path.join(outdir, "sandbox_logs.json"), "wb")

    # Collect logs and store them at the output location
    process = subprocess.call(["log", "show",
                     "--start", start,
                     "--end", end,
                     "--style", "json",
                     "--predicate", 'senderImagePath == "/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox"'],
                    stdout = outfile)


if __name__ == "__main__":
    main()
