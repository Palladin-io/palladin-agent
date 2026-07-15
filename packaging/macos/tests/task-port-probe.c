#include <errno.h>
#include <limits.h>
#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  if (argc != 2) {
    fputs("usage: task-port-probe PID\n", stderr);
    return 64;
  }
  errno = 0;
  char *end = NULL;
  long parsed = strtol(argv[1], &end, 10);
  if (errno != 0 || end == argv[1] || *end != '\0' || parsed <= 0 || parsed > INT_MAX) {
    fputs("invalid PID\n", stderr);
    return 64;
  }
  mach_port_t task = MACH_PORT_NULL;
  kern_return_t result = task_for_pid(mach_task_self(), (pid_t)parsed, &task);
  if (result == KERN_SUCCESS) {
    if (task != MACH_PORT_NULL) {
      (void)mach_port_deallocate(mach_task_self(), task);
    }
    fputs("task_for_pid unexpectedly opened the signed runtime\n", stderr);
    return 1;
  }
  puts("task_for_pid was denied.");
  return 0;
}
