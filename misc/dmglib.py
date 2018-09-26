"""
DiskImage (.dmg) support.

This module can be used to attach and detach disk images, to check a disk image's
validity and to query certain information (password-protected, license agreement included)
about already verified disk images.

Tested with 10.13.6 and Python 3.7.

Due to the usage of the capture_output parameter in subprocess.run,
the program will not work unchanged in older python versions. However,
the changes required to make it work for older python versions should
be neglible.
"""
import plistlib
import subprocess
import os
import enum
from contextlib import contextmanager


class HdiutilNotFound(Exception):
	"""
	The required hdiutil tool could not be found.
	"""
	pass


class InvalidDiskImage(Exception):
	"""
	The disk image is invalid and cannot be attached, according to the
	DiskImage.is_valid function.
	"""
	pass


class InvalidOperation(Exception):
	"""
	Raised when the user attempts to perform an invalid operation, such as
	trying to attach an already attached dmg or trying to detach a dmg that
	has not been attached previously.
	"""
	pass


class AttachingFailed(Exception):
	pass


class AlreadyAttached(AttachingFailed):
	pass


class PasswordRequired(AttachingFailed):
	"""
	Mounting requires a password but none provided.
	"""
	pass


class PasswordIncorrect(AttachingFailed):
	"""
	Invalid password supplied for disk image
	"""
	pass


class LicenseAgreementNeedsAccepting(AttachingFailed):
	"""
	Some DMGs come with a license agreement that needs
	to be accepted prior to mounting the DMG.
	"""
	pass


class DetachingFailed(Exception):
	"""
	Could not detach volume successfully.
	"""
	pass


def raw_hdiutil(args, input : bytes = None) -> (int, bytes):
	"""
	Invokes the hdiutil command with the supplied arguments.
	Returns a tuple containing the return code and the output
	of stdout.
	"""
	hdiutil_path = '/usr/bin/hdiutil'
	if not os.path.exists(hdiutil_path):
		raise HdiutilNotFound()

	completed = subprocess.run([hdiutil_path] + args, 
		input=input, capture_output=True)

	return (completed.returncode, completed.stdout)


def hdiutil(args, no_plist=False, keyphrase=None) -> (bool, dict):
	"""
	Calls the command line 'hdiutil' binary.
	Returns whether the operation was successful and a dictionary containing
	the decoded plist response (None if the operation failed).
	"""
	assert '-plist' not in args

	# The no_plist parameters is needed for certain operations that do not
	# support the -plist flag.
	if not no_plist:
		args.append('-plist')

	if keyphrase is not None:
		args.append('-stdinpass')

	returncode, output = raw_hdiutil(args, input=keyphrase.encode('utf8') if keyphrase else None)
	if returncode != 0:
		return False, dict()

	if not no_plist:
		return True, plistlib.loads(output)
	else:
		return True, dict()


def hdiutil_isencrypted(path) -> bool:
	"""
	Check whether a disk image located at `path` is encrypted.
	If it is encrypted, all other commands that attempt to extract
	information or attach the disk image fail or hang indefinitely.
	"""
	success, result = hdiutil(['isencrypted', path])

	return success and result.get('encrypted', False)


def hdiutil_imageinfo(path, keyphrase=None) -> (bool, dict):
	return hdiutil(['imageinfo', path], keyphrase=keyphrase)


def hdiutil_attach(path, keyphrase=None) -> (bool, dict):
	return hdiutil([
		'attach',
		path,
		'-nobrowse' # Do not make the mounted volumes visible in Finder.app
	], keyphrase=keyphrase)


def hdiutil_detach(dev_node, force=False) -> bool:
	success, _ = hdiutil(['detach', dev_node] + (['-force'] if force else []), no_plist=True)
	return success


def hdiutil_info() -> (bool, dict):
	return hdiutil(['info'])


def attached_images() -> list:
	success, infos = hdiutil_info()

	return [ image['image-path'] 
		for image in infos.get('images', []) 
		if 'image-path' in image ]


class MountedVolume:
	def __init__(self, mount_point, volume_kind):
		self.mount_point = mount_point
		self.volume_kind = volume_kind


class DMGState(enum.Enum):
	DETACHED = enum.auto()
	ATTACHED = enum.auto()


class DMGStatus:
	def __init__(self):
		self.status = DMGState.DETACHED
		self.mount_points = []
		self.root_dev_entry = None

	def is_attached(self) -> bool:
		return self.status == DMGState.ATTACHED

	def record_attached(self, paths, root_dev_entry):
		self.status = DMGState.ATTACHED
		self.mount_points = paths
		self.root_dev_entry = root_dev_entry

	def record_detached(self):
		self.status = DMGState.DETACHED
		self.mount_points = []


class DiskImage:
	@staticmethod
	def is_encrypted(path: str) -> bool:
		"""
		Returns whether the current DMG is encrypted / password protected.

		Note: As the encrypted status is only available after obtaining
		the disk image's information through hdiutil_imageinfo and thus
		after requiring the correct password, this function instead uses
		a different data source and is a static method that can be called
		at any time.
		"""
		return hdiutil_isencrypted(path)


	@staticmethod
	def check_keyphrase(path: str, keyphrase: str) -> bool:
		"""
		Check whether the keyphrase is valid for the disk image at path.

		Only call this method if the supplied disk image is encrypted!
		"""
		if not DiskImage.is_encrypted(path):
			raise InvalidOperation('DiskImage is not encrypted')

		success, _ = hdiutil_imageinfo(path, keyphrase=keyphrase)
		return success


	@staticmethod
	def is_already_attached(path: str) -> bool:
		"""
		Check whether the supplied disk image has already been attached
		previously. If so, then querying the system for information about
		this image fails with a resource exhaustion error message.
		"""
		return os.path.realpath(path) in attached_images()


	@staticmethod
	def is_valid(path: str) -> bool:
		"""
		Check whether the supplied candidate disk image is a valid disk image.

		A disk image is valid according to this logic, if it is either not encrypted
		and valid according to hdiutil, or encrypted according to hdiutil.

		This method shall not raise any exceptions
		"""
		if DiskImage.is_encrypted(path):
			return True

		success, _ = hdiutil_imageinfo(path)
		return success


	def __init__(self, path, keyphrase=None):
		"""
		Initialize a disk image object from a given filesystem path and
		optional keyphrase.

		This method may throw the following exceptions:
		- AlreadyAttached: If the disk image was already attached on the target
		system
		- InvalidDiskImage: If the disk image is not a valid disk image.
		- PasswordRequired / PasswordIncorrect: These exceptions are thrown if the
		image is encrypted but none or invalid passwords are supplied.
		"""
		# The hdiutil fails when the target path has already been mounted / attached.
		if DiskImage.is_already_attached(path):
			raise AlreadyAttached()

		if not DiskImage.is_valid(path):
			raise InvalidDiskImage()

		if DiskImage.is_encrypted(path) and keyphrase is None:
			raise PasswordRequired()

		if DiskImage.is_encrypted(path) and not DiskImage.check_keyphrase(path, keyphrase):
			raise PasswordIncorrect()

		self.path 		= path
		self.keyphrase  = keyphrase
		_, self.imginfo	= hdiutil_imageinfo(path, keyphrase=keyphrase)
		self.status 	= DMGStatus()


	def _lookup_property(self, property_name, default_value):
		return self.imginfo\
			.get('Properties', dict())\
			.get(property_name, default_value)


	def has_license_agreement(self) -> bool:
		"""
		Returns whether the current disk image has an attached license agreement.

		DMGs with license agreements can only be attached with user input.
		"""
		return self._lookup_property('Software License Agreement', False)


	def attach(self) -> str:
		"""
		Attaches the DMG. Returns the resulting mount point.
		"""
		if self.status.is_attached():
			raise InvalidOperation()

		if self.has_license_agreement():
			raise LicenseAgreementNeedsAccepting()

		success, result = hdiutil_attach(self.path, keyphrase=self.keyphrase)
		if not success:
			raise AttachingFailed('Attaching failed for unknown reasons.')

		mounted_volumes = [ MountedVolume(mount_point=entity['mount-point'], 
										  volume_kind=entity['volume-kind'])
			for entity in result.get('system-entities', []) 
			if 'mount-point' in entity and 'volume-kind' in entity ]

		if len(mounted_volumes) == 0:
			raise AttachingFailed('Attaching the disk image mounted no volumes.')

		# The root dev entry is the smallest '/dev/disk...' entry when sorted
		# lexicographically. (/dev/disk2 < /dev/disk3 < /dev/disk3s1)
		# In the case of disk images containing APFS volumes, we need to detach this disk _after_
		# detaching the main volumes. This is an Apple bug -- for all other types of volumes,
		# detaching the volume automatically detaches the entire disk image.
		root_dev_entry = sorted(entity['dev-entry']
			for entity in result.get('system-entities', [])
			if 'dev-entry' in entity)[0]

		self.status.record_attached(mounted_volumes, root_dev_entry)
		return [ volume.mount_point for volume in self.status.mount_points ]


	def detach(self, force=True):
		if not self.status.is_attached():
			raise InvalidOperation()

		# Detaching any mount point of an attached image automatically unmounts
		# all associated volumes.
		# ... unless one of these volumes is an APFS volume. In that case,
		# it needs to be detached separately. Additionally, the root dev entry
		# also needs to be detached explicitly.

		# First detach all APFS volumes, otherwise detaching other volumes succeeds
		# but fails with an error code (!)
		for volume in self.status.mount_points:
			if volume.volume_kind == 'apfs':
				success = hdiutil_detach(volume.mount_point, force=force)
				if not success:
					raise DetachingFailed()

		# Finally, detach the root dev entry.
		success = hdiutil_detach(self.status.root_dev_entry, force=force)
		if not success:
			raise DetachingFailed()

		self.status.record_detached()


@contextmanager
def attachedDiskImage(path: str, keyphrase=None):
	"""
	Context manager for working with disk images.

	The context manager returns the list of mount points of the attached volumes.
	There is always at least one mount point available, otherwise attaching fails.
	Note that the caller needs to catch exceptions (see __init__() and attach()),
	or call the appropriate functions (is_encrypted, is_valid, check_keyphrase) beforehand.

	Example usage:
	```
	with dmg.attachedDiskImage('path/to/disk_image.dmg', 
			keyphrase='sample') as mount_points:
		print(mount_points)
	```
	"""
	dmg = DiskImage(path, keyphrase=keyphrase)
	try:
		yield dmg.attach()
	finally:
		if dmg.status.is_attached():
			dmg.detach()

