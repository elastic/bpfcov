# bpfcov / cli

> Run your instrumented eBPF programs and obtain coverage from them

## Usage

Once you have [built](#building) it, you can use the **bpfcov** CLI following the next steps.

First, **run** your eBPF program through it:

```shell
$ sudo ./bpfcov -v2 run ../examples/src/.output/cov/raw_enter
```

Notice that you must give to the `run` subcommand the **instrumented eBPF program** (`.output/`**cov**`/raw_enter`).

To know how to instrument it please [read this section](...).

When the eBPF program completed, or when you stopped the `run` subcommand, you may want to double-check
that **bpfcov** created **its pinned eBPF maps** in the BPF file system.

```shell
$ sudo tree /sys/fs/bpf/cov

/sys/fs/bpf/cov
└── raw_enter
    ├── covmap
    ├── profc
    ├── profd
    └── profn
```

If so, then it is time to **generate** a `.profraw` file by collecting info from those eBPF maps!

To do so, you need to use the `gen` subcommand:

```shell
sudo ./bpfcov -v2 gen ../examples/src/.output/cov/raw_enter
```

This command will create a `raw_enter.profraw` file sibling to the instrumented eBPF program (thus, in `../examples/src/.output/cov/raw_enter.profraw`).

By default, the `gen` subcommand will **not** unpin the eBPF maps that the `run` subcommand created.

But in case you want to unpin them, and you want to output the `.profraw` file in a different location, you can do the following command:

```shell
sudo ./bpfcov -v2 gen --unpin -o hellow.profraw ../examples/src/.output/cov/raw_enter
```

Now that you have a fresh `.profraw` file you can use the **LLVM tools** ([llvm-profdata](https://llvm.org/docs/CommandGuide/llvm-profdata.html), and [llvm-cov](https://llvm.org/docs/CommandGuide/llvm-cov.html)) as usual to get a nice **source-based coverage** report out of it.

For example, you may want to generate a `*.profdata` file:

```shell
$ llvm-profdata merge -sparse hellow.profraw -o hellow.profdata
```

With such a file, plus the `*.bpf.obj` file created while instrumenting your eBPF program ([read this if you haven't](...)), you can now obtain various coverage reports!

```shell
$ llvm-cov show \
  --instr-profile=hellow.profdata \
  --show-region-summary --show-branch-summary --show-line-counts-or-regions \
  ../examples/src/.output/cov/raw_enter.bpf.obj
```

The previous command will output the annotated source code to `stdout`:

```
    1|       |#include "vmlinux.h"
    2|       |#include <asm/unistd.h>
    3|       |#include <bpf/bpf_helpers.h>
    4|       |#include <bpf/bpf_core_read.h>
    5|       |#include <bpf/bpf_tracing.h>
    6|       |
    7|       |char LICENSE[] SEC("license") = "GPL";
    8|       |
    9|       |const volatile int count = 0;
   10|       |
   11|       |SEC("raw_tp/sys_enter")
   12|       |int BPF_PROG(hook_sys_enter)
   13|      1|{
   14|      1|  bpf_printk("ciao0");
   15|       |
   16|      1|  struct trace_event_raw_sys_enter *x = (struct trace_event_raw_sys_enter *)ctx;
   17|      1|  if (x->id != __NR_connect)
   18|      1|  {
   19|      0|    return 0;
   20|      0|  }
   21|       |
   22|     10|  for (int i = 1; i < count; i++)
                ^1                         ^9
   23|      9|  {
   24|      9|    bpf_printk("ciao%d", i);
   25|      9|  }
   26|       |
   27|      1|  return 0;
   28|      1|}
```

You can also output a JSON report, or an HTML one. It's your call!

Feel free to explore the different flags the **bpfcov** CLI and its subcommand supports by reading their manual (more in the [help section](#help)).

## Help

The **bpfcov** CLI provides a detailed `--help` flag.

```shell
$ ./bpfcov --help

Usage: bpfcov [OPTION...] [run|gen] <program>

Obtain coverage from your instrumented eBPF programs.

  OPTIONS:
      --bpffs=path           Set the BPF FS path (defaults to /sys/fs/bpf)
  -v, --verbose[=level]      Set the verbosity level when not built for release
                             (defaults to 0)


  GLOBALS:
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.

  EXAMPLES:
  bpfcov run <program>
  bpfcov gen <program>

...
```

It also provides a specific `--help` flag for each subcommand.

For example, you can get to know more about the `gen` subcommand by typing:

```shell
$ ./bpfcov gen --help

Usage: bpfcov gen [OPTION...] <program>

Generate the profraw file for the bpfcov instrumented program.


  OPTIONS:
  -o, --output=path          Set the output path
                             (defaults to <program>.profraw)
      --unpin                Unpin the maps


  GLOBALS:
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version
```

Feel free to explore the other subcommands and their flags.

## Building

I'm not sure this topic requires a whole section on its own:

```shell
make
```

🎈
