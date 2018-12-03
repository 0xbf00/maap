#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "apple_sandbox.h"

const int BUFSIZE = 1024;

bool process_is_sandboxed(pid_t pid) {
    return sandbox_check(pid, NULL, 0) == 1;
}

int main(int argc, char *argv[]) {
    if (argc <= 1) {
        fprintf(stderr, "Usage: %s pid\n", argv[0]);
        return EXIT_FAILURE;
    }

    for (int i = 1; i < argc; ++i) {
        const long pid = strtol(argv[i], NULL, 10);

        if (pid == 0 && errno == EINVAL) {
            fprintf(stderr, "Invalid PID: '%s'\n", argv[i]);
            return EXIT_FAILURE;
        }

        if (kill(pid, 0) != 0 && errno == ESRCH) {
            fprintf(stderr, "No such process: '%s'\n", argv[i]);
            return EXIT_FAILURE;
        }

        if (!process_is_sandboxed(pid)) {
            fprintf(stderr, "Process not sandboxed: '%s'\n", argv[i]);
            return EXIT_FAILURE;
        }

        char container_path[BUFSIZE];
        int status = sandbox_container_path_for_pid(pid, container_path, BUFSIZE);

        if (status != 0) {
            fprintf(stderr, "Error determining container of process (permission denied?): '%s'\n", argv[i]);
            return status;
        }

        printf("%s\n", container_path);
    }

    return EXIT_SUCCESS;
}
