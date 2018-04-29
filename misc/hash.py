"""Functions to hash files."""

from hashlib import sha256


def hash_file(algorithm, filepath: str) -> str:
    """
    Returns the hash of a file using a specific algorithm.

    :param algorithm: The algorithm to use. Should be an object of the haslib class such as hashlib.sha256
    :param filepath: File to hash
    :return: Hexdigest encoded as a string.
    """
    # 1 MB
    BLOCK_SIZE = 1024 * 1024

    with open(filepath, "rb") as infile:
        hash = algorithm()

        buf = infile.read(BLOCK_SIZE)
        while len(buf) > 0:
            hash.update(buf)
            buf = infile.read(BLOCK_SIZE)

        return hash.hexdigest()


def sha256_file(filepath: str) -> str:
    """Returns the SHA256 of a file as denoted by ``filepath``"""
    return hash_file(sha256, filepath)


