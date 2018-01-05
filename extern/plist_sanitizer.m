/**
 * (C) Jakob Rieck 2018
 *
 * This program reads plist files from the command line, parses them using
 * the standard Apple NSDictionary APIs and writes them back to the filesystem.
 * This is done because Apple's API are much more resilient to malformed property
 * lists, as compared to Python's plistlib implementation. In case of errors
 * by the Python API, the plist is first converted and then the converted file
 * is read by Python API.
 **/
#import <Foundation/Foundation.h>

#define LOG(str, args...) do { fprintf(stderr, "\x1b[91m" str "\x1b[0m\n", ##args); } while(0)

int main(int argc, char *argv[])
{
	if (argc != 2 && argc != 3) {
		LOG("Usage: %s plist [outfile]\n", argv[0]);
		return EXIT_FAILURE;
	}

	char * const plistFile = argv[1];
	NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile: [NSString stringWithUTF8String: plistFile]];
	if (!dict) {
		LOG("Failed to open input file.\nEnsure you have read permissions to the input directory");
		return EXIT_FAILURE;
	}

	if (argc == 3) {
		char * const outFile = argv[2];
		if (YES != [dict writeToFile: [NSString stringWithUTF8String: outFile] atomically: YES]) {
			LOG("Failed to write output file to disk.\nEnsure you have write permissions to the output directory.");
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}
