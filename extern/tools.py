import os.path
import subprocess


def _invoke_tool(filepath, *args, **kwargs):
    if not os.path.exists(filepath):
        raise FileNotFoundError

    cmd = [filepath, *args]
    try:
        kwargs.update({
            'stderr': subprocess.DEVNULL
        })
        result = subprocess.check_output(cmd, **kwargs)
        return (0, result)
    except subprocess.CalledProcessError as err:
        return (err.returncode, err.output)


def tool_named(name):
    """
    Returns a function object that can be used to directly invoke the tool's CLI.

    This is handled transparently through the use of the subprocess library.
    The returned function will
        - Raise the FileNotFoundError if the tool does not exist
        - Return a tuple (exit_code, stdout_output) in all other cases
    """
    tool_path = os.path.join(os.path.dirname(__file__), name)
    return lambda *args, **kwargs: _invoke_tool(tool_path, *args, **kwargs)


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
    simbple_func = tool_named("simbple")

    if result_format != "scheme" and result_format != "json":
        raise ValueError("Invalid format specified.")

    simbple_args = [f"--{result_format}", os.path.join(container, "Container.plist")]
    if patch:
        simbple_args.append("--patch")

    exit_code, output = simbple_func(*simbple_args)

    if exit_code != 0:
        return
    
    return output