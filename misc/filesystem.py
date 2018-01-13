"""Filesystem related util functions"""
import os.path
from misc.hash import sha256_file


def is_same_file(fileA, fileB):
    if os.path.samefile(fileA, fileB):
        return True
    else:
        # For some developers, using the proper Framework format appears to be impossible.
        # Most commonly, developers end up copying the executable into another folder.
        # This obviously blows up the resulting bundle size.
        # To detect these cases, a candidate bundle is accepted, if the underlying files
        # are identical (those advertised by the framework and the one returned by our bundle.framework
        # implementation)
        hash_a = sha256_file(fileA)
        hash_b = sha256_file(fileB)
        return hash_a == hash_b


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