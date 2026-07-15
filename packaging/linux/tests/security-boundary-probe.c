#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <unistd.h>

static int denied(int result) {
    return result == -1 && (errno == EPERM || errno == EACCES);
}

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    char *end = NULL;
    long value = strtol(argv[1], &end, 10);
    if (end == argv[1] || *end != '\0' || value <= 1) return 64;
    pid_t pid = (pid_t)value;

    errno = 0;
    int ptrace_result = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    int ptrace_denied = denied(ptrace_result);
    if (ptrace_result == 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
    }

    char local = 0;
    struct iovec local_iov = { .iov_base = &local, .iov_len = 1 };
    struct iovec remote_iov = { .iov_base = (void *)1, .iov_len = 1 };
    errno = 0;
    ssize_t vm_result = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
    int vm_denied = vm_result == -1 && (errno == EPERM || errno == EACCES || errno == ESRCH);

    const char *suffixes[] = { "mem", "environ", "fd" };
    int proc_denied = 1;
    for (size_t index = 0; index < sizeof(suffixes) / sizeof(suffixes[0]); index++) {
        char path[128];
        snprintf(path, sizeof(path), "/proc/%ld/%s", (long)pid, suffixes[index]);
        errno = 0;
        int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (descriptor >= 0) {
            proc_denied = 0;
            close(descriptor);
        } else if (errno != EPERM && errno != EACCES && errno != ENOENT) {
            proc_denied = 0;
        }
    }

    printf("ptrace=%s process_vm_readv=%s proc=%s\n",
           ptrace_denied ? "denied" : "not-denied",
           vm_denied ? "denied" : "not-denied",
           proc_denied ? "denied" : "not-denied");
    return ptrace_denied && vm_denied && proc_denied ? 0 : 1;
}
