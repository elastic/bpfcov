#define _GNU_SOURCE

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

#define FATAL(...)                               \
    do                                           \
    {                                            \
        fprintf(stderr, "bpfcov: " __VA_ARGS__); \
        fputc('\n', stderr);                     \
        exit(EXIT_FAILURE);                      \
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
    logfile = stdout;

    if (argc <= 1)
        FATAL("too few arguments: %d", argc);

    pid_t pid = fork();
    switch (pid)
    {
    case -1: /* error */
        FATAL("%s", strerror(errno));
    case 0: /* child */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
        {
            FATAL("%s", strerror(errno));
        }
        execvp(argv[1], argv + 1);
        FATAL("%s", strerror(errno));
    }

    /* parent */
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
        fprintf(logfile, "%d(%d, %ld, %ld, %ld, %ld, %ld)",
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
            fprintf(logfile, " = ?\n");
            if (errno == ESRCH)
                exit(regs.rdi); // system call was _exit(2) or similar
            FATAL("%s", strerror(errno));
        }

        /* Print system call result */
        long result = regs.rax;
        fprintf(logfile, " = %ld\n", result);


    }
}
