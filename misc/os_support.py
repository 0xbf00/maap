"""
os_support.py

(c) Jakob Rieck 2018

Query the currently installed macOS version. Compare different macOS version numbers
to check what programs are compatible with older systems.
"""
import platform

def os_release() -> str:
	"""
	Obtain the os's release version string.
	For the last high sierra release, this function returns
	10.13.6 (at the time of writing this)
	"""
	assert(platform.system() == 'Darwin')

	ver, _, _ = platform.mac_ver()

	return ver


def os_is_compatible(required_os_version: str) -> bool:
	"""
	Check whether the currently installed OS is compatible with
	the minimum version supplied in `required_os_version`.
	We assume that all macOS versions are backwards-compatible, that is
	10.12 binaries run on 10.13, but not the other way around.
	"""
	current_version = [int(c) for c in os_release().split('.')]
	required_version = [int(c) for c in required_os_version.split('.')]

	# 10.13.6.2 is not (necessarily) compatible with 10.13.6
	if len(required_version) > len(current_version) and\
	   required_version[0:len(current_version)] == current_version:
	   return False

	# Compare versions component-wise
	for (c, r) in zip(current_version, required_version):
		if c < r:
			return False

	return True

