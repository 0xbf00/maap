"""
lief_extensions.py
(c) Jakob Rieck 2018

Useful extensions to the lief API
"""
import lief


def macho_parse_quick(path: str):
	"""
	lief.parse by default does a deep parsing. However, for the purposes
	of this work, a quick parse suffices. This function does the appropriate
	parsing and returns the last binary in a fat binary (same as lief.parse does)
	"""
	assert lief.is_macho(path)

	bin = lief.MachO.parse(path, config=lief.MachO.ParserConfig.quick)
	if bin is None:
		return

	return bin.at(bin.size - 1)
