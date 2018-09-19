import os.path
import subprocess

from misc.filesystem import project_path


def tool_named(name):
    """Returns the full filepath to the specified tool.
    Raises an exception if tool does not exist."""
    tool_path = os.path.join(os.path.dirname(__file__), name)
    if not os.path.exists(tool_path):
        raise ValueError("Tool does not exist.")
    return tool_path


def call_sbpl(container, result_format = 'scheme', patch = False):
    """
    Uses custom sbpl interpreter to compile metadata for a given container.
    Optionally also supports patching the profile (adding report modifiers to
    each allow rule) and supports two different result formats.

    :param container: Filepath to container. Container must contain the Container.plist
                      metadata file
    :param result_format: 'scheme' or 'json', the supported data files
    :param patch: Whether to add report modifiers to each allow rule,
                  forcing the sandbox to log every operation
    :return: Compiled sandbox profile as bytes
    """
    sbpl_base_dir = project_path("simbple")
    sbpl_tool = os.path.join(sbpl_base_dir, "build/bin/simbple")

    if result_format != "scheme" and result_format != "json":
        raise ValueError("Invalid format specified.")

    try:
        cmd = [sbpl_tool, "--" + result_format, os.path.join(container, "Container.plist")]

        if patch:
            cmd.append("--patch")

        result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, cwd=sbpl_base_dir)
        return result
    except subprocess.CalledProcessError:
        return None