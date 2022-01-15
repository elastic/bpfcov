# bpfcov / cli

> Run your instrumented eBPF programs and obtain coverage from them

## Usage

Once you have [built](#building) it, you can use the **bpfcov** CLI following the next steps.

First, **run** your eBPF application through it:

```bash
$ sudo ./bpfcov -v2 run ../examples/src/.output/cov/raw_enter
```

Notice that you must give to the `run` subcommand the **instrumented eBPF application** (`.output/`**cov**`/raw_enter`).

To know how to instrument it please [read this section](../README#usage).
Or just take a look at the [examples](../examples) directory...

When the eBPF application exited, or when you stopped the `run` subcommand, you may want to double-check
that **bpfcov** created **its pinned eBPF maps** in the BPF file system.

```bash
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

```bash
sudo ./bpfcov -v2 gen ../examples/src/.output/cov/raw_enter
```

This command will create a `raw_enter.profraw` file sibling to the instrumented eBPF application binary (thus, in `../examples/src/.output/cov/raw_enter.profraw`).

By default, the `gen` subcommand will **not** unpin the eBPF maps that the `run` subcommand created.

But in case you want to unpin them, and you want to output the `.profraw` file in a different location, you can do the following command:

```bash
sudo ./bpfcov -v2 gen --unpin -o hellow.profraw ../examples/src/.output/cov/raw_enter
```

Now that you have a fresh `.profraw` file you can use the **LLVM tools** ([llvm-profdata](https://llvm.org/docs/CommandGuide/llvm-profdata.html), and [llvm-cov](https://llvm.org/docs/CommandGuide/llvm-cov.html)) as usual to get a nice **source-based coverage** report out of it.

Or you can use `bpfcov cov ...`!

It acts as an opinionated wrapper to the `llvm-profdata` and `llvm-cov` commands you'd need to execute manually otherwise. [This sections](#generating-coverage-reports) shows how it works!

Anyways, here's how to output a source-based code coverage report to the standard output starting from the `*.profraw` file we just generated.

First, generate a `*.profdata` file:

```bash
$ llvm-profdata merge -sparse hellow.profraw -o hellow.profdata
```

With such a file, plus the `*.bpf.obj` file created while instrumenting your eBPF program ([read this if you haven't](../examples/README.md#key-aspects)), you can now obtain various coverage reports!

```bash
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

You can also output a JSON report, a LCOV, or an HTML one (see [the next section](generating-coverage-reports)). It's your call!

Feel free to explore the different flags the **bpfcov** CLI and its subcommand supports by reading their manual (more in the [help section](#help)).

### Generating coverage reports

This section shows how to generate code coverage reports for your eBPF programs, either via the **bpfcov** CLI (more straightforward) or manually.

It shows how to do it for a few eBPF applications in a single report, either HTML, json, or lcov.

But the same applies if you only have one eBPF application for which you want to generate a report.

Assuming we have gerenated with `bpfcov gen ...` the `*.profraw` files for 3 examples,
we can generate a **HTML* report for all of them:

```bash
./bpfcov -v2 cov -o awesome_html_cov_report \
  ../examples/src/.output/cov/lsm.profraw ../examples/src/.output/cov/fentry.profraw ../examples/src/.output/cov/fentry.profraw
````

Generating a **JSON** report it's just a matter of specifing the format:

```bash
./bpfcov -v2 cov --format=json \
  ../examples/src/.output/cov/lsm.profraw ../examples/src/.output/cov/fentry.profraw ../examples/src/.output/cov/fentry.profraw
```

By default, the `cov` subcommand will output in `out.json` when the `--output` flag is not specified.

No need to repeat myself showing the `lcov` format... Right?

Just in case you need to fine-tune the coverage report by passing different arguments to `llvm-cov`,
here is how to manually do the same things the `bpfcov cov` command does.

1. Generate the `*.profdata` files from your `*.profraw` ones:

```bash
llvm-profdata merge -sparse ../examples/src/.output/cov/lsm.profraw -o lsm.profdata
llvm-profdata merge -sparse ../examples/src/.output/cov/fentry.profraw -o fentry.profdata
llvm-profdata merge -sparse ../examples/src/.output/cov/raw_enter.profraw -o raw_enter.profdata
```

2. Merge all of them in a single `all.profdata` file:

```bash
llvm-profdata merge \
  -sparse lsm.profdata fentry.profdata raw_enter.profdata \
  -o all.profdata
```

3. Play with `llvm-cov` to outpu your **HTML** coverage report, for example:

```bash
llvm-cov show --format=html \
  --show-branches=count --show-line-counts-or-regions --show-region-summary \
  -instr-profile=all.profdata \
  -object ../examples/src/.output/cov/raw_enter.bpf.obj -object ../examples/src/.output/cov/fentry.bpf.obj -object ../examples/src/.output/cov/lsm.bpf.obj \
  --output-dir=../yay
```

Notice that this is the step where you need the `*.bpf.obj` archive files!

4. Want to export an **lcov** representation of the coverage and generate a line coverage HTML report only?

```bash
llvm-cov export --format=lcov \
  --show-region-summary --show-branch-summary \
  -instr-profile=all.profdata \
  -object ../examples/src/.output/cov/raw_enter.bpf.obj -object ../examples/src/.output/cov/fentry.bpf.obj -object ../examples/src/.output/cov/lsm.bpf.obj > all.info
genhtml all.info --legend --show-details --highlight --output-directory ../lcov_line_coverage
```

## Help

The **bpfcov** CLI provides a detailed `--help` flag.

```bash
$ ./bpfcov --help

Usage: bpfcov [OPTION...] [run|gen|cov] <arg(s)>

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
  bpfcov cov <program.profraw>+

...
```

It also provides a specific `--help` flag for each subcommand.

For example, you can get to know more about the `gen` subcommand by typing:

```bash
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

```bash
make
```

🎈
