"""Functionality related to listing and querying apps"""
import os
import subprocess
import logging

from bundle.bundle import Bundle, InvalidBundle
from binary.binary import Binary
from extern.tools import tool_named, call_sbpl


def all_apps(at: str = "/Applications", mas_only: bool = False, sandboxed_only: bool = False):
    '''
    Returns all apps from a target folder

    :param at: The base folder where to search for applications
    :param mas_only: Whether to only consider applications from the Mac App Store
    :param sandboxed_only: Whether to only return sandboxed applications
    :return: Filepaths to applications fulfilling the criteria specified
    '''
    all_entries = [ os.path.join(at, x) for x in os.listdir(at) if x.endswith(".app") ]

    for entry in all_entries:
        try:
            app_bundle = Bundle.make(entry)
            if mas_only and not app_bundle.is_mas_app():
                continue
            if sandboxed_only and not app_bundle.is_sandboxed():
                continue
            yield entry
        except InvalidBundle:
            continue


def container_for_app(app):
    '''
    Returns the container directory used by the application or None if the container does not exist.

    :param app: The app for which to find the container directory. Note that valid arguments are both
                a filepath to the application and a bundle for that application
    :return: Filepath to the container or None, if the lookup failed.
    '''
    # Handle code that already has a bundle for an app
    if isinstance(app, Bundle):
        app_bundle = app
    elif isinstance(app, str):
        try:
            app_bundle = Bundle.make(app)
        except InvalidBundle:
            return None

    bid = app_bundle.bundle_identifier()

    # Verify the container exists.
    container_path = os.path.join(os.path.expanduser("~/Library/Containers/"), bid)
    if not os.path.exists(container_path):
        return None

    # Also verify that the metadata file is present, else the container is invalid and of
    # no use to other code
    container_metadata = os.path.join(container_path, "Container.plist")
    if not os.path.exists(container_path):
        return None

    return container_path


def _entitlements_can_be_parsed(app_bundle: Bundle) -> bool:
    '''
    Check whether an application's entitlements can be parsed by libsecinit.
    We only check part of the process, namely the parsing of entitlements via xpc_create_from_plist.

    :param app_bundle: Bundle for which to check whether the entitlements can be parsed
    :type app_bundle: Bundle

    :return: True, iff the entitlements of the main executable can be parsed, else false.
    '''
    # No entitlements, no problem
    # If the app contains no entitlements, entitlement validation cannot fail.
    if not app_bundle.has_entitlements():
        return True

    exe_path = app_bundle.executable_path()
    raw_entitlements = Binary.get_entitlements(exe_path, raw=True)

    # Call the local xpc_vuln_checker program that does the actual checking.
    return_value = subprocess.run([tool_named("xpc_vuln_checker")], input=raw_entitlements)

    return return_value.returncode != 1


def init_sandbox(app_bundle: Bundle, logger: logging.Logger, force_initialisation: bool = False) -> bool:
    '''
    Initialises the sandbox for a particular app bundle.

    :param app_bundle: The App for which to initialise the App Sandbox
    :param logger: Logger object used to record failure cases
    :param force_initialisation: Whether to overwrite / start initialisation even if metadata
           exists that indicates the sandbox has already been initialised
    :return: Boolean value indicating whether the sandbox was successfully initialised
             (or was already initialised)
    '''
    # Guarding against a few applications that ship with entitlements libsecinit cannot parse.
    if not _entitlements_can_be_parsed(app_bundle):
        return False

    # Super useful environment variable used by libsecinit. If this variable is set, the application
    # is terminated after its sandbox is initialised.
    init_sandbox_environ = {**os.environ, 'APP_SANDBOX_EXIT_AFTER_INIT': str(1)}

    app_container = container_for_app(app_bundle)
    if app_container is not None and not force_initialisation:
        if logger:
            logger.info("Container directory already existed. Skipping sandbox initialisation.")
        return True

    if logger:
        logger.info("Starting process {} to initialize sandbox.".format(app_bundle.executable_path()))
    process = subprocess.Popen([app_bundle.executable_path()],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL,
                               env=init_sandbox_environ)

    # Sandbox initialisation should be almost instant. If the application is still
    # running after a couple of seconds, the sandbox failed to initialise.
    # We use 10 seconds as an arbitrary cutoff time.
    try:
        process.wait(10)
    except subprocess.TimeoutExpired:
        process.kill()
        if logger:
            logger.error("Sandbox was not initialised successfully for executable at {}. Skipping.".format(
                app_bundle.executable_path())
            )
        return False

    # Check that there now is an appropriate container
    if container_for_app(app_bundle) is None:
        if logger:
            logger.info(
                "Sandbox initialisation for executable {} succeeded \
                but no appropriate container metadata was created.".format(
                    app_bundle.executable_path()
                )
            )
        return False

    return True


def run_process(executable, duration, stdout_file=subprocess.DEVNULL, stderr_file=subprocess.DEVNULL) -> int:
    '''
    Executes and runs a process for a certain number of seconds, then kills the process.
    :param executable: Filepath to executable to execute
    :param duration: Duration in seconds or None to let the executable run indefinitely.
    :param stdout_file: File object to write standard output to
    :param stderr_file: File object to write standard error to
    :return: The PID of the running process
    '''
    process = subprocess.Popen([executable], stdout=stdout_file, stderr=stderr_file)

    process_pid = process.pid

    try:
        process.wait(duration)
    except subprocess.TimeoutExpired:
        process.kill()

    return process_pid


def get_sandbox_rules(app_bundle, result_format: str = 'scheme', patch: bool = False):
    '''
    Obtain the final sandbox ruleset for a target application. Optionally
    also patches the result so that all allow decisions are logged to the
    syslog.

    :param app_bundle: The bundle for which to obtain the sandbox ruleset
    :param result_format: The format to return. Supported are \"scheme\" and \"json\"
    :param patch: Whether to patch the resulting profile. Patching a profile results
                  in a profile that logs all allowed decisions.
    :return: Raw bytes of sandbox profile.
    '''
    container = container_for_app(app_bundle)

    return call_sbpl(container, result_format=result_format, patch=patch)