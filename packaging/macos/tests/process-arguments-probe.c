#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <unistd.h>

static int contains(const unsigned char *haystack, size_t haystack_length,
                    const unsigned char *needle, size_t needle_length) {
    if (needle_length == 0 || needle_length > haystack_length) return 0;
    for (size_t index = 0; index + needle_length <= haystack_length; index++) {
        if (memcmp(haystack + index, needle, needle_length) == 0) return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) return 64;
    char *end = NULL;
    long parsed = strtol(argv[1], &end, 10);
    if (end == argv[1] || *end != '\0' || parsed <= 0 || parsed > INT_MAX) return 64;

    char expected[PATH_MAX] = {0};
    char actual[PROC_PIDPATHINFO_MAXSIZE] = {0};
    if (realpath(argv[2], expected) == NULL ||
        proc_pidpath((int)parsed, actual, sizeof(actual)) <= 0) return 1;
    char canonical_actual[PATH_MAX] = {0};
    if (realpath(actual, canonical_actual) == NULL || strcmp(expected, canonical_actual) != 0) return 1;

    unsigned char canary[129] = {0};
    ssize_t canary_length = read(STDIN_FILENO, canary, sizeof(canary));
    if (canary_length < 32 || canary_length > 128) return 64;

    int argument_maximum = 0;
    size_t argument_maximum_size = sizeof(argument_maximum);
    int maximum_query[] = {CTL_KERN, KERN_ARGMAX};
    if (sysctl(maximum_query, 2, &argument_maximum, &argument_maximum_size, NULL, 0) != 0 ||
        argument_maximum <= 0 || argument_maximum > 16 * 1024 * 1024) return 1;

    unsigned char *arguments = calloc(1, (size_t)argument_maximum);
    if (arguments == NULL) return 1;
    size_t arguments_size = (size_t)argument_maximum;
    int process_query[] = {CTL_KERN, KERN_PROCARGS2, (int)parsed};
    int result = sysctl(process_query, 3, arguments, &arguments_size, NULL, 0);
    if (result != 0) {
        free(arguments);
        return errno == EPERM ? 1 : 1;
    }
    int leaked = contains(arguments, arguments_size, canary, (size_t)canary_length);
    memset(arguments, 0, arguments_size);
    free(arguments);
    memset(canary, 0, sizeof(canary));
    if (leaked) return 2;
    puts("process-arguments-environment=canary-absent");
    return 0;
}
