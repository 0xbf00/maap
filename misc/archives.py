import tempfile
import gzip
import zipfile
import tarfile
import os
import misc.filesystem as fs

resolved = lambda x: os.path.realpath(os.path.abspath(x))

def badpath(path, base):
    # joinpath will ignore base if path is absolute
    return not resolved(os.path.join(base,path)).startswith(base)

def badlink(info, base):
    # Links are interpreted relative to the directory containing the link
    tip = resolved(os.path.join(base, os.path.dirname(info.name)))
    return badpath(info.linkname, base=tip)

def safemembers(members):
    base = resolved(".")

    for finfo in members:
        if badpath(finfo.name, base):
            pass
        elif finfo.issym() and badlink(finfo,base):
            pass
        elif finfo.islnk() and badlink(finfo,base):
            pass
        else:
            yield finfo


class SafeTarFile(tarfile.TarFile):
    def extractall_safe(self, path='.'):
        """
        Extract all members that are deemed safe from the archive to the current
        directory or directory `path`
        """
        return self.extractall(path, members=safemembers(self))


def extract_gzip(path: str, to: str) -> (bool, str):
	"""
	Attempts to extract a gzip file into the supplied temporary
	directory.

	Returns whether the operation was successful and the filepath
	to the extracted file.

	The tar file code can already decompress tar.gz archives.
	However, there are also cases where DMG images are compressed
	using gzip, or other cases where the tarfile module fails.
	"""
	gzip_file = gzip.GzipFile(path)

	handle, temp = tempfile.mkstemp(dir=to)
	try:
		n_written = os.write(handle, gzip_file.read())
		if n_written <= 0:
			raise OSError('Did not write any output')

		fs.rchmod(to, 0o755)
		return True, temp
	except OSError:
		# Remove temporary file from filesystem if unpack fails. Otherwise,
		# because an empty file is processed successfully by this function, we
		# might get an infinite loop in future calls when processing the containing
		# directory.
		os.remove(temp)
		return False, None
	finally:
		os.close(handle)


def zip_is_password_protected(path) -> bool:
	try:
		with zipfile.ZipFile(path) as zipf:
			zipf.testzip()
			return False
	except (zipfile.BadZipFile, RuntimeError) as e:
		return 'encrypted' in str(e)


def extract_zip(path: str, to: str) -> bool:
	"""
	Extracts a zip file into a temporary directory.
	Returns whether the operation was successful.
	"""
	if not zipfile.is_zipfile(path):
		return False

	if zip_is_password_protected(path):
		return False

	try:
		with zipfile.ZipFile(path, 'r') as archive:
			# Extract contents to temporary directory
			archive.extractall(to)
			# Set filesystem access permissions to 755, otherwise it
			# is possible for the clean up operation to fail due to permission
			# errors. Since we do not execute the applications, changing permissions
			# has no negative impact here.
			fs.rchmod(to, 0o755)

			return True
	except zipfile.BadZipFile:
		return False


def extract_tar(path: str, to: str) -> bool:
	"""
	Process a given file as a tar file.
	Returns whether the operation was successful.
	"""
	if not tarfile.is_tarfile(path):
		return False

	try:
		with SafeTarFile(path) as tar:	
			tar.extractall_safe(to)
			# Necessary, see comment in extract_zip function
			fs.rchmod(to, 0o755)

			return True
	except tarfile.ReadError:
		return False
