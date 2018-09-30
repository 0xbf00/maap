"""Filesystem related utility functions"""
import os
import shutil

from .hash import sha256_file


def is_same_file(pathA: str, pathB: str) -> bool:
    """
    Checks whether two files actually refer to the same file.
    :param pathA: First filepath
    :param pathB: Second filepath to check against first filepath
    :return: True, if the files refer to the same file or they have the same contents (as measured
             by their hash). This is a workaround for a problem where developers duplicate a bunch
             of application content, because they apparently do not realise how file linking works.
    """
    if os.path.samefile(pathA, pathB):
        return True
    else:
        # For some developers, using the proper Framework format appears to be impossible.
        # Most commonly, developers end up copying the executable into another folder.
        # This obviously blows up the resulting bundle size.
        # To detect these cases, a candidate bundle is accepted, if the underlying files
        # are identical (those advertised by the framework and the one returned by our bundle.framework
        # implementation)
        hash_a = sha256_file(pathA)
        hash_b = sha256_file(pathB)
        return hash_a == hash_b


def path_remove_prefix(path: str, prefix: str) -> str:
    """
    Removes a prefix from a path string, if the path has such a prefix.
    """
    if path.startswith(prefix):
        return path[len(prefix):]
    return path


def get_size(path):
    """
    Returns the total size of entries in `path` if path
    denotes a directory. Otherwise simply returns the size
    in bytes of the file
    """
    if os.path.isdir(path):
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                total_size += os.path.getsize(fp)
        return total_size
    else:
        return os.path.getsize(path)


def project_root():
    """
    Returns root directory of project
    """
    return os.path.realpath(os.path.join(os.path.basename(__file__), "../.."))


def project_path(relative_path = ''):
    """
    Returns a full path to a file, identified by its relative path from the project root
    """
    return os.path.join(project_root(), relative_path)


def copy(src, dst):
    """
    Copies data from `src` to `dst`.

    Like shutil's copy2, this function attempts to copy all relevant file
    metadata. However unlike copy2, this function will not hard fail when
    metadata cannot be copied.

    Executables protected by SIP for example cannot be copied successfully
    using shutil's copy2.
    """
    shutil.copy(src, dst)
    try:
        shutil.copystat(src, dst)
    except PermissionError:
        pass
