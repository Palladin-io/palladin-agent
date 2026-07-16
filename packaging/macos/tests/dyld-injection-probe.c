#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) static void palladin_dyld_probe(void) {
  const char *marker = getenv("PALLADIN_DYLD_PROBE_MARKER");
  if (marker == NULL || marker[0] == '\0') {
    return;
  }
  int descriptor = open(marker, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (descriptor >= 0) {
    (void)write(descriptor, "injected", 8);
    (void)close(descriptor);
  }
}
