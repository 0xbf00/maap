"""Functionality related to listing and querying apps"""
import os
from bundle.bundle import Bundle
import subprocess
import tempfile

def all_apps(at = "/Applications", mas_only = False):
    """Generator for all applications installed in a certain folder.
    Optionally: Returns only MAS apps"""
    all_entries = [os.path.join(at, x) for x in os.listdir(at)]
    filtered_entries = filter(lambda x: x.endswith(".app"), all_entries)

    for entry in filtered_entries:
        if mas_only:
            try:
                app_bundle = Bundle.make(entry)
                if app_bundle.is_mas_app():
                    yield entry
            except:
                continue
        else:
            yield entry


def all_sandboxed_apps(at = "/Applications", mas_only = False):
    """Generator for all sandboxed apps.
    Optionally: returns only sandboxed apps from the MAS."""
    underlying_apps = all_apps(at) if not mas_only else all_mas_apps(at)

    for app in underlying_apps:
        try:
            app_bundle = Bundle.make(app)
            if app_bundle.is_sandboxed():
                yield app
        except:
            continue


def container_for_app(app):
    """Returns the container directory used by the application or None if the container does not exist."""
    try:
        # Handle code that already has a bundle for an app
        if isinstance(app, Bundle):
            app_bundle = app
        elif isinstance(app, str):
            app_bundle = Bundle.make(app)

        app_bundleid = app_bundle.bundle_identifier()

        # Verify the container exists.
        container_path = os.path.join(os.path.expanduser("~/Library/Containers/"), app_bundleid)
        if not os.path.exists(container_path):
            return None

        # Also verify that the metadata file is present, else the container is invalid and of
        # no use to other code
        container_metadata = os.path.join(container_path, "Container.plist")
        if not os.path.exists(container_path):
            return None

        return container_path
    except:
        return None


def init_sandbox(app_bundle, logger, force_initialisation = False):
    # In order to patch and re-generate the sandbox profile used by an application,
    # we needs its Container metdata, which is generated during profile generation.
    # As such, we first start the app, let the sandbox do its job, then exit.
    # Thankfully, Apple provides an environment variable that does just that.
    init_sandbox_environ = {**os.environ, 'APP_SANDBOX_EXIT_AFTER_INIT': str(1)}

    app_container = container_for_app(app_bundle)
    if app_container is not None and not force_initialisation:
        logger.info("Container directory already existed. Skipping sandbox initialisation.")
        return True

    logger.info("Starting process {} to initialize sandbox.".format(app_bundle.executable_path()))
    process = subprocess.Popen([app_bundle.executable_path()], env = init_sandbox_environ)

    # Sandbox initialisation should be almost instant. If the application is still
    # running after a couple of seconds, the sandbox failed to initialise.
    # We use 10 seconds as an arbitrary cutoff time.
    try:
        process.wait(10)
    except subprocess.TimeoutExpired:
        process.kill()
        logger.error("Sandbox was not initialised successfully for executable at {}. Skipping.".format(
            app_bundle.executable_path())
        )
        return False

    # Check that there now is an appropriate container
    if container_for_app(app_bundle) is None:
        logger.info(
            "Sandbox initialisation for executable {} succeeded but no appropriate container metadata was created.".format(
                app_bundle.executable_path()
            )
        )
        return False

    return True


def run_process(executable, duration, stdout_file = subprocess.DEVNULL, stderr_file = subprocess.DEVNULL):
    """Executes and runs a process for a certain number of seconds. Then kills the process.
    Returns the PID of the process"""

    process = subprocess.Popen([executable], stdout=stdout_file, stderr=stderr_file)

    process_pid = process.pid

    try:
        process.wait(duration)
    except subprocess.TimeoutExpired:
        process.kill()

    return process_pid


def get_sandbox_rules(app_bundle, result_format = "scheme", patch = False):
    """Returns the final sandboxing ruleset for an application. Optionally
    also patches the result so that all allow decisions are logged to the
    syslog.

    :param result_format The format to return. Supported are \"scheme\" and \"json\"
    :param patch Whether to patch the resulting profile. Patching a profile results
    in a profile that logs all allowed decisions.
    :returns Raw bytes of sandbox profile."""

    sbpl_base_dir = os.path.join(os.path.dirname(__file__), "../../sbpl")
    assert os.path.exists(sbpl_base_dir)
    sbpl_tool = os.path.join(sbpl_base_dir, "build/sbpl")
    application_base_profile = os.path.join(sbpl_base_dir, "application.sb")
    assert os.path.exists(sbpl_tool)
    assert os.path.exists(application_base_profile)

    if result_format != "scheme" and result_format != "json":
        raise ValueError("Invalid format specified.")

    try:
        cmd = [sbpl_tool,
               "--" + result_format,
               "--bundle-id", app_bundle.bundle_identifier(),
               "--profile", application_base_profile]
        if patch:
            cmd.append("--patch")

        result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, cwd=sbpl_base_dir)
        return result
    except subprocess.CalledProcessError:
        return None