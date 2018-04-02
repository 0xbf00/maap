import os.path

def tool_named(name):
    """Returns the full filepath to the specified tool.
    Raises an exception if tool does not exist."""
    tool_path = os.path.join(os.path.dirname(__file__), name)
    if not os.path.exists(tool_path):
        raise ValueError("Tool does not exist.")
    return tool_path