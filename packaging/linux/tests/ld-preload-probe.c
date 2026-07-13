#include <fcntl.h>
#include <unistd.h>

#ifndef PALLADIN_PROBE_PATH
#define PALLADIN_PROBE_PATH "/run/palladin-runtime/ld-preload-hit"
#endif

__attribute__((constructor)) static void palladin_preload_probe(void) {
    int descriptor = open(PALLADIN_PROBE_PATH, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (descriptor >= 0) close(descriptor);
}
