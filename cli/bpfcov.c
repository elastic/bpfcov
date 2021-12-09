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
#include <sys/stat.h>
#include <sys/vfs.h>

/* Linux */
#include <syscall.h>
#include <sys/ptrace.h>
#include <linux/limits.h>
#include <linux/magic.h>
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

static void replace_with(char *s, const char what, const char with);
int make_pin_path(const char *root, const char *prog_name, const char *map_name, char **pin_path);

int main(int argc, char **argv)
{
    /* Defaults */
    logfile = stdout;              // TODO(leodido) > make configurable
    path_root = "/sys/fs/bpf/cov"; // TODO(leodido) > make configurable + sanitize (remove last slash and dots)

    /* Pre-flight checks */
    if (argc <= 1)
    {
        FATAL("too few arguments: %d", argc);
    }
    // TODO(leodido) > check bpffs is mounted
    if (mkdir(path_root, 0700) && errno != EEXIST)
    {
        FATAL("cannot create pinning root: %s", path_root);
    }

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
        {
            FATAL("%s", strerror(errno));
        }
        if (waitpid(pid, 0, 0) == -1)
        {
            FATAL("%s", strerror(errno));
        }

        /* Gather system call arguments */
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        {
            FATAL("%s", strerror(errno));
        }

        const unsigned int sysc = regs.orig_rax;
        const unsigned int comm = regs.rdi;

        /* Print a representation of the system call */
        PRINT("%d(%d, %ld, %ld, %ld, %ld, %ld)",
              sysc,
              comm, (long)regs.rsi, (long)regs.rdx,
              (long)regs.r10, (long)regs.r8, (long)regs.r9);

        if (sysc == SYS_bpf && comm == BPF_MAP_CREATE)
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
            fprintf(logfile, "%s\n", " = ?");
            if (errno == ESRCH)
            {
                exit(regs.rdi); // _exit(2) or similar
            }
            FATAL("%s", strerror(errno));
        }

        /* Print system call result */
        long result = regs.rax;
        fprintf(logfile, " = %ld\n", result);

        /* Pin the bpfcov maps */
        if (is_map && result)
        {
            int pidfd = syscall(SYS_pidfd_open, pid, 0);
            if (pidfd < 0)
            {
                continue;
            }
            int curfd = syscall(SYS_pidfd_getfd, pidfd, result, 0);
            if (curfd < 0)
            {
                continue;
            }

            struct bpf_map_info map_info = {};
            memset(&map_info, 0, sizeof(map_info));
            unsigned int len = sizeof(map_info);

            int err;
            err = bpf_obj_get_info_by_fd(curfd, &map_info, &len);
            if (!err && strlen(map_info.name) > 0)
            {
                const char *sep = ".";
                strtok(map_info.name, sep);
                char *suffix = strtok(NULL, sep);

                if (strncmp(suffix, "profc", 5) == 0 || strncmp(suffix, "profd", 5) == 0 || strncmp(suffix, "profn", 5) == 0)
                {
                    char *pin_path;
                    if (make_pin_path(path_root, target, suffix, &pin_path))
                    {
                        if (access(pin_path, F_OK) == 0)
                        {
                            PRINT("pin path already exists: %s\n", pin_path);
                            // TODO(leodido) > make this behavior configurable: ignore, delete and pin again, error out
                            continue;
                        }

                        err = bpf_obj_pin(curfd, pin_path);
                        if (err)
                        {
                            FATAL("cannot pin map: %s", pin_path);
                        }
                        PRINT("pinning successful: %s\n", pin_path);
                    }
                }
            }
        }
    }
}

static void replace_with(char *s, const char what, const char with)
{
    while (*s)
    {
        if (*s == what)
        {
            *s = with;
        }
        s++;
    }
}

int make_pin_path(const char *root, const char *prog_name, const char *map_name, char **pin_path)
{
    char dir[PATH_MAX];
    int dirlen = snprintf(dir, PATH_MAX, "%s/%s", root, prog_name);
    if (dirlen < 0)
    {
        FATAL("pin directory too short");
        goto error_out;
    }
    else if (dirlen >= PATH_MAX)
    {
        FATAL("pin directory too long");
        goto error_out;
    }

    char *dir_path = strdup(dir);
    replace_with(dir_path, '.', '_');

    if (mkdir(dir_path, 0700) && errno != EEXIST)
    {
        FATAL("cannot create pin path: %s", dir_path);
        goto error_out;
    }

    struct statfs stats;
    if (statfs(dir_path, &stats))
    {
        FATAL("cannot get pin directory filesystem statistics: %s", dir_path);
        goto error_out;
    }
    if (stats.f_type != BPF_FS_MAGIC)
    {
        FATAL("pin directory not on BPF filesystem: %s", dir_path);
        goto error_out;
    }

    char path[PATH_MAX];
    int pathlen = snprintf(path, PATH_MAX, "%s/%s", dir_path, map_name);
    if (pathlen >= PATH_MAX)
    {
        FATAL("pin path too long");
    }
    *pin_path = path;

    free(dir_path);

    return 1;

error_out:
    return 0;
}