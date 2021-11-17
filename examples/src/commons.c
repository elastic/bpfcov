#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stdout, format, args);
}

static void bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new))
    {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }
}

static volatile sig_atomic_t stop;

void sig_int(int signo)
{
    stop = signo;
}

int bpf_trace_pipe(int out)
{
    // todo > find mount -> use mnt/trace_pipe (making strong assumptions atm)

    int inp = STDERR_FILENO;
    inp = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY);
    if (inp < 0)
    {
        return inp;
    }

    while (!stop)
    {
        static char buf[4096];
        ssize_t ret;

        ret = read(inp, buf, sizeof(buf));
        if (ret > 0 && write(out, buf, ret) == ret)
        {
            continue;
        }
    }

    close(inp);
    return 0;
}