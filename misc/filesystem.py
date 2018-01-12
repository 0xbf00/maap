"""Filesystem related util functions"""
import os.path


def path_remove_prefix(path: str, prefix: str) -> str:
    """Removes a prefix from a path string, if the path has such a prefix."""
    if path.startswith(prefix):
        return path[len(prefix):]
    return path


def get_size(path):
    """Returns the total size of entries in `path` if path
    denotes a directory. Otherwise simply returns the size
    in bytes of the file"""
    if os.path.isdir(path):
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                total_size += os.path.getsize(fp)
        return total_size
    else:
        return os.path.getsize(path)