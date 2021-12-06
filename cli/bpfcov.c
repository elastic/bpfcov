#define _GNU_SOURCE

#ifdef NDEBUG
#define DEBUG 0
#else
#define DEBUG 1
#endif

/* C standard library */
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* POSIX */
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>

/* Linux */
#include <syscall.h>
#include <sys/ptrace.h>
#include <bpf/bpf.h>

static FILE *logfile;
const char *path_root;

#define FATAL(...)                               \
    do                                           \
    {                                            \
        fprintf(stderr, "bpfcov: " __VA_ARGS__); \
        fputc('\n', stderr);                     \
        exit(EXIT_FAILURE);                      \
    } while (0)

#define PRINT(fmt, ...)                                    \
    do                                                     \
    {                                                      \
        if (DEBUG)                                         \
            fprintf(logfile, "bpfcov: " fmt, __VA_ARGS__); \
    } while (0)

static inline int sys_pidfd_getfd(int pidfd, int fd, int flags)
{
    return syscall(__NR_pidfd_getfd, pidfd, fd, flags);
}

static inline int sys_pidfd_open(pid_t pid, unsigned int flags)
{
    return syscall(SYS_pidfd_open, pid, flags);
}

int main(int argc, char **argv)
{
    /* Defaults */
    logfile = stdout;          // TODO(leodido) > make configurable
    path_root = "/sys/fs/bpf"; // TODO(leodido) > make configurable

    /* Pre-flight checks */
    if (argc <= 1)
        FATAL("too few arguments: %d", argc);
    // TODO(leodido) > check bpffs is mounted

    const char *target = basename(argv[1]);

    pid_t pid = fork();
    switch (pid)
    {
    case -1: /* Error */
        FATAL("%s", strerror(errno));
    case 0: /* Child */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
        {
            FATAL("%s", strerror(errno));
        }
        execvp(argv[1], argv + 1);
        FATAL("%s", strerror(errno));
    }

    /* Parent */
    waitpid(pid, 0, 0); // sync with PTRACE_TRACEME
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

    int is_map = 0;
    for (;;)
    {
        /* Enter next system call */
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));
        if (waitpid(pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));

        /* Gather system call arguments */
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
            FATAL("%s", strerror(errno));

        const unsigned int syscall = regs.orig_rax;
        const unsigned int command = regs.rdi;

        /* Print a representation of the system call */
        PRINT("%d(%d, %ld, %ld, %ld, %ld, %ld)",
              syscall,
              command, (long)regs.rsi, (long)regs.rdx,
              (long)regs.r10, (long)regs.r8, (long)regs.r9);

        if (syscall == SYS_bpf && command == BPF_MAP_CREATE)
        {
            is_map = 1;
        }

        /* Run system call and stop on exit */
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));
        if (waitpid(pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));

        /* Get system call result */
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        {
            PRINT("%s\n", " = ?");
            if (errno == ESRCH)
                exit(regs.rdi); // _exit(2) or similar
            FATAL("%s", strerror(errno));
        }

        /* Print system call result */
        long result = regs.rax;
        PRINT(" = %ld\n", result);
    }
}
