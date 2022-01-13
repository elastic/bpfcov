// SPDX-License-Identifier: GPL-2.0-only
#include "vmlinux.h"
#include <asm/unistd.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

const volatile int count = 0;

SEC("raw_tp/sys_enter")
int BPF_PROG(hook_sys_enter)
{
  bpf_printk("ciao0");

  struct trace_event_raw_sys_enter *x = (struct trace_event_raw_sys_enter *)ctx;
  if (x->id != __NR_connect)
  {
    return 0;
  }

  for (int i = 1; i < count; i++)
  {
    bpf_printk("ciao%d", i);
  }

  return 0;
}