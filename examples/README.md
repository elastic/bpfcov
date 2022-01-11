# bpfcov / examples

Here (in the `src/` directory) you will find some eBPF programs to demonstrate the usage of `libBPFCov.so`.

## Overview

Every example is composed by:

1. a `*.bpf.c` file that contains the eBPF program
2. a `*.c` file that contains the userspace code

The [Makefile](src/Makefile) generates 2 targets for each word of the [EXAMPLES](src/Makefile#L20) variable in it.

So, assuming the `EXAMPLES` variable contains a word `foo`, then the following targets will be generated:

1. `make foo`

    It outputs a your eBPF application binary in `.output/foo`

2. `make cov/foo`

    It outputs an eBPF application binary **instrumented for source-based code coverage** in `.output/cov/foo`

In case you wanna try **bpfcov** on another example, doing it is just a matter of putting its source code in the `src/` directory and appending its name into the `EXAMPLES variable in the [Makefile](src/Makefile).

The [Makefile](src/Makefile) takes care of everything... But I suggest you to take a look at it in case you are interested into getting to know the details of the steps. Or at least, read the following [section](#key-aspects).

## Key aspects

The key aspects of building an instrumented eBPF application are the following ones.

1. Compile you eBPF program (`*.bpf.c`) to LLVM IR instrumenting it with profile and coverage mapping information (`-fprofile-instr-generate -fcoverage-mapping`)

2. Run the pass (`libBPFCov.so`) on the LLVM IR to fix it for the BPF VM

    1. Use it to compile a valid BPF ELF that loads successfully in the Linux kernel

3. Run _again_ the pass (`libBPFCov.so`) with the `-strip-initializers-only` flag on the LLVM IR

    1. Use the resulting LLVM IR to compile a (valid but not loading) BPF ELF (`*.bpf.obj`)
    2. It will serve you as one of the inputs for `llvm-cov`

4. Userspace code compilation as usual but using the instrumted ELF from step 2

## Usage

Did you already take a look at the [requirements](#requirements) section?

Do you only wanna build a specific eBPF example application as is?

Good!

```shell
make fentry
```

Do you only wanna compile a specific eBPF example application instrumented for code coverage?

Even better!

```shell
make cov/fentry
```

Wanna build everything?

```shell
make
```

Wanna start over but not recompile the dependencies too?

```shell
make clean
```

Wanna start from scratch?

```shell
make distclean
```

## Requirements

1. `libBPFCov.so`

    First [obtain](../README.md#Building) the LLVM pass library, please.

2. `bpftool`

    You can provide your own `bpftool` by putting it in the `tools` directory.

    Otherwise the [Makefile](src/Makefile) will try to find it in the system path and symlink it into the `tools/` directory.

    In any case you will need a `bpftool` that supports the **skeletons** feature becase this tool uses **custom eBPF sections** for storing the instrumentation and coverage mapping data.

3. `libbpf`

    Ensure you have the git submodule in the `libbpf/` directory.
