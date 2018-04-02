/**
 * (C) Jakob Rieck 2018
 * 
 * Simple program that reads an input file and determines 
 * whether the xpc_create_from_plist would correctly parse
 * the file or not. Parsing failure could allow exploitation
 * of the App Sandbox.
 **/

#include <stdlib.h>
#include <xpc/xpc.h>
#include <assert.h>

// 1MB
#define BUFSIZE (1024 * 1024)

extern xpc_object_t xpc_create_from_plist(void *data, size_t len);

int main(int argc, char *argv[])
{
    // allocate 1mb buffer size, this should suffice for all entitlement plists
    void *buffer = calloc(BUFSIZE, 1);
    assert(buffer);

    const size_t size = fread(buffer, 1, BUFSIZE, stdin);
    assert(size < BUFSIZE);

    xpc_object_t dict = xpc_create_from_plist(buffer, size);
    if (!dict) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}