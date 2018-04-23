from hashlib import sha256


def hash_file(algorithm, filepath: str) -> str:
    """Returns the hash of a file (using the algorithm ``algorithm``) as denoted by ``filepath``

    The algorithm should be an object of the hashlib class. One
    example would be hash_file(hashlib.sha256, "/tmp/file1")
    Deals with large files by iteratively reading in the file (block size is 1MB at the
    moment) and iteratively updating the hash.
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

    return None


def sha256_file(filepath: str) -> str:
    """Returns the SHA256 of a file as denoted by ``filepath``"""
    return hash_file(sha256, filepath)


