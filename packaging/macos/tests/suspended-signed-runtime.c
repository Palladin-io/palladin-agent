#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static volatile sig_atomic_t stop_requested = 0;

static void request_stop(int signal_number) {
  (void)signal_number;
  stop_requested = 1;
}

int main(int argc, char **argv) {
  if (argc != 2) return 64;
  struct sigaction action = { .sa_handler = request_stop };
  if (sigaction(SIGTERM, &action, NULL) != 0 || sigaction(SIGINT, &action, NULL) != 0) return 1;

  posix_spawnattr_t attributes;
  if (posix_spawnattr_init(&attributes) != 0) return 1;
  if (posix_spawnattr_setflags(&attributes, POSIX_SPAWN_START_SUSPENDED) != 0) {
    posix_spawnattr_destroy(&attributes);
    return 1;
  }
  char *const arguments[] = { argv[1], "doctor", NULL };
  pid_t child = 0;
  int result = posix_spawn(&child, argv[1], NULL, &attributes, arguments, environ);
  posix_spawnattr_destroy(&attributes);
  if (result != 0) return 1;

  printf("%ld\n", (long)child);
  fflush(stdout);
  for (int seconds = 0; seconds < 60 && !stop_requested; ++seconds) sleep(1);
  kill(child, SIGKILL);
  waitpid(child, NULL, 0);
  return stop_requested ? 0 : 124;
}
