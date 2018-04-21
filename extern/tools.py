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
    sbpl_base_dir = project_path("sbpl")
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
               "--container", container,
               "--profile", application_base_profile]
        if patch:
            cmd.append("--patch")

        result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, cwd=sbpl_base_dir)
        return result
    except subprocess.CalledProcessError:
        return None