/**
 * Copyright (C) Jakob Rieck, 2018
 *
 * Check whether other processes are sandboxed.
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>

#include "apple_sandbox.h"

int process_is_sandboxed(pid_t pid)
{
	return sandbox_check(pid, NULL, 0);
}

int main(int argc, char *argv[])
{
	if (argc <= 1) {
		fprintf(stderr, "Usage: %s pid\n", argv[0]);
		return EXIT_FAILURE;
	}

	for (int i = 1; i < argc; ++i) {
		long pid = strtol(argv[i], NULL, 10);

		if (pid == 0 && errno == EINVAL) {
			fprintf(stderr, "Invalid PID: '%s'\n", argv[i]);
			return EXIT_FAILURE;
		}

		if (kill(pid, 0) != 0 && errno == ESRCH) {
		    fprintf(stderr, "No such process: '%s'\n", argv[i]);
		    return EXIT_FAILURE;
        }

		printf("Sandbox status for PID %ld is %d\n", 
			pid, process_is_sandboxed(pid));
	}

	return EXIT_SUCCESS;
}
