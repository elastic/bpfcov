#include <asm/unistd.h>
#include <bpf/bpf.h>
#include "commons.c"
#include "raw_enter.skel.h"

struct trace_entry
{
    short unsigned int type;
    unsigned char flags;
    unsigned char preempt_count;
    int pid;
};

struct trace_event_raw_sys_enter
{
    struct trace_entry ent;
    long int id;
    long unsigned int args[6];
    char __data[0];
};

int main(int argc, char **argv)
{
    struct raw_enter *skel;
    int err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
    bump_memlock_rlimit();

    if (signal(SIGINT, sig_int) == SIG_ERR || signal(SIGTERM, sig_int) == SIG_ERR)
    {
        fprintf(stderr, "Can't handle Ctrl-C: %s\n", strerror(errno));
        goto cleanup;
    }

    /* Open load and verify BPF application */
    skel = raw_enter__open();
    if (!skel)
    {
        fprintf(stderr, "Can't open the BPF skeleton\n");
        return 1;
    }

    // Set the counter
    skel->rodata->count = 10;

    err = raw_enter__load(skel);
    if (err)
    {
        fprintf(stderr, "Can't load the BPF skeleton\n");
        goto cleanup;
    }
    fprintf(stdout, "BPF skeleton OK\n");

    int prog_fd = bpf_program__fd(skel->progs.hook_sys_enter);
    fprintf(stdout, "BPF program FD: %d\n", prog_fd);
    struct trace_event_raw_sys_enter ctx = {
        .id = __NR_connect,
    };

    struct bpf_prog_test_run_attr tattr = {};
    tattr.prog_fd = prog_fd;
    tattr.repeat = 0;
    tattr.ctx_in = &ctx;
    tattr.ctx_size_in = sizeof(ctx);

    err = bpf_prog_test_run_xattr(&tattr);

cleanup:
    raw_enter__destroy(skel);
    return -err;
}