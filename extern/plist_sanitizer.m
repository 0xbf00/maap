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
	if (argc != 1) {
		LOG("This program reads its input from stdin and writes its output to stdout.");
		LOG("The return code indicates whether the operation was successful (0) or not.");
		return EXIT_FAILURE;
	}

	NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile: @"/dev/stdin"];
	if (!dict) {
		LOG("Failed to read / decode input.");
		return EXIT_FAILURE;
	}

	if (YES != [dict writeToFile: @"/dev/stdout" atomically: YES]) {
		LOG("Failed to write output to stdout.");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
