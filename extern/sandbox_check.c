#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>

enum sandbox_filter_type {
    SANDBOX_FILTER_NONE,
    SANDBOX_FILTER_PATH,
    SANDBOX_FILTER_GLOBAL_NAME,
    SANDBOX_FILTER_LOCAL_NAME,
    SANDBOX_FILTER_APPLEEVENT_DESTINATION,
    SANDBOX_FILTER_RIGHT_NAME,
    SANDBOX_FILTER_PREFERENCE_DOMAIN,
    SANDBOX_FILTER_KEXT_BUNDLE_ID,
    SANDBOX_FILTER_INFO_TYPE,
    SANDBOX_FILTER_NOTIFICATION,
};
extern const enum sandbox_filter_type SANDBOX_CHECK_NO_REPORT;
extern const enum sandbox_filter_type SANDBOX_CHECK_CANONICAL;
extern const enum sandbox_filter_type SANDBOX_CHECK_NOFOLLOW;

int sandbox_check(pid_t pid, const char *operation,
                  int type, ...);

int sandbox_init_with_parameters(const char *profile, uint64_t flags, const char *const parameters[], char **errorbuf);

int sandbox_check_all(pid_t pid, const char *op, const char *argument)
{
    struct sb_check_argument {
        int type;
        bool arg_required;
    };

    const struct sb_check_argument all_checks[] = {
        { SANDBOX_FILTER_NONE, false },
        { SANDBOX_FILTER_PATH, true },
        { SANDBOX_FILTER_GLOBAL_NAME, true },
        { SANDBOX_FILTER_LOCAL_NAME, true },
        { SANDBOX_FILTER_APPLEEVENT_DESTINATION, true },
        { SANDBOX_FILTER_RIGHT_NAME, true },
        { SANDBOX_FILTER_PREFERENCE_DOMAIN, true },
        { SANDBOX_FILTER_KEXT_BUNDLE_ID, true },
        { SANDBOX_FILTER_INFO_TYPE, true },
        { SANDBOX_FILTER_NOTIFICATION, true }
    };

    const pid_t process_pid = getpid();

    for (size_t i = 0;
         i < sizeof(all_checks) / sizeof(*all_checks);
         ++i) 
    {
        int decision = -1;

        if (all_checks[i].arg_required) {
            decision = sandbox_check(process_pid, op,
                SANDBOX_CHECK_NO_REPORT | all_checks[i].type,
                argument);
        } else {
            decision = sandbox_check(process_pid, op,
                SANDBOX_CHECK_NO_REPORT | all_checks[i].type);
        }

        if (decision == 0) {
            return 0;
        }
    }

    return 1;
}

// 10MB of memory
#define BUFSIZE (10 * 1024 * 1024)

int main(int argc, char *argv[])
{
    if (argc <= 1) {
        return EXIT_FAILURE;
    }

    // Read sandbox profile from stdin
    char *sandbox_profile = calloc(1, BUFSIZE);
    assert(sandbox_profile != NULL);

    size_t bytes_read = fread(sandbox_profile, 1, BUFSIZE, stdin);
    assert(bytes_read < BUFSIZE);

    // Initialize sandbox
    char *error = NULL;
    int rv = sandbox_init_with_parameters(sandbox_profile, 0, NULL, &error);
    assert(!error && (rv == 0));

    return sandbox_check_all(getpid(), argv[1], argv[2]);
}