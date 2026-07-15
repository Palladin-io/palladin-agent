#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef PALLADIN_PROBE_PATH
#define PALLADIN_PROBE_PATH "/run/palladin-runtime/ld-preload-hit"
#endif

__attribute__((constructor)) static void palladin_preload_probe(void) {
    const char *marker = PALLADIN_PROBE_PATH;
#ifdef PALLADIN_PROBE_DIRECTORY
    char executable[4096] = {0};
    char categorized_marker[4096] = {0};
    ssize_t length = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
    const char *category = "other";
    if (length > 0) {
        executable[length] = '\0';
        if (strstr(executable, "memfd:palladin-worker") != NULL) {
            category = "worker";
        } else if (strstr(executable, "palladin-linux-client") != NULL) {
            category = "client";
        } else {
            const char *basename = strrchr(executable, '/');
            basename = basename == NULL ? executable : basename + 1;
            if (strcmp(basename, "node") == 0) category = "node";
        }
    }
    int written = snprintf(categorized_marker, sizeof(categorized_marker), "%s/%s.hit",
                           PALLADIN_PROBE_DIRECTORY, category);
    if (written > 0 && (size_t)written < sizeof(categorized_marker)) marker = categorized_marker;
#endif
    int descriptor = open(marker, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (descriptor >= 0) close(descriptor);
}
