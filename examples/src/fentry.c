// SPDX-License-Identifier: GPL-2.0
#include "commons.c"
#include "fentry.skel.h"

int main(int argc, char **argv)
{
	struct fentry *skel;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
	bump_memlock_rlimit();

	/* Open load and verify BPF application */
	skel = fentry__open_and_load();
	if (!skel)
	{
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	err = fentry__attach(skel);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR)
	{
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
		   "to see output of the BPF programs.\n");

	while (!stop)
	{
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	fentry__destroy(skel);
	return -err;
}
