# bpfcov

> Source-code based coverage for eBPF programs actually running in the Linux kernel

This project provides 2 main components:

1. `libBPFCov.so` - an **out-of-tree LLVM pass** to **instrument** your **eBPF programs** for coverage.
2. `bpfcov` - a **CLI** to **collect source-based coverage** from your eBPF programs.

**TBD: SCREENSHOTS GRID**

## Overview

This section aims to provide a high-level overiew of the steps you need to get started with **bpfcov**.

1. [Compile the LLVM pass](#building) obtaining `libBPFCov.so`
2. Instrument your eBPF program by compiling it and by running the LLVM pass on it
3. Build the userspace code of your eBPF application
4. Execute your eBPF application in the kernel through the `bpfcov run ...` command
5. Generate the `.profraw` file from the run through the `bpfcov gen ...` command
6. Use the LLVM toolchain to create coverage reports as documented in the [LLVM docs](https://clang.llvm.org/docs/SourceBasedCodeCoverage.html#creating-coverage-reports)

In case you are impatient and want to jump straight into getting your hands dirty, then the [examples](examples/) directory contains a few dummy eBPF programs to showcase what **bpfcov** does.

It basically automates steps 2 and 3. Its [README](examples/README.md) contains more details.

While the [README of the cli directory](cli/README.md) gives you more details about the steps 4 and 5 (and also 6).

## Usage

Here I will highlight the _manual_ steps to use it.

I suggest you to automate most of them like I did in the [examples Makefile](examples/src/Makefile).

Anyway, assuming you have [built](#building) the LLVM pass, you can then use your fresh `libBPFCov.so` to instrument your eBPF programs for coverage (steps 2 and 3 above).

How to do it?

First, you need to compile your eBPF program almost as usual but to LLVM IR...

```bash
clang -g -O2 \
    -target bpf -D__TARGET_ARCH_x86 -I$(YOUR_INCLUDES) \
    -fprofile-instr-generate -fcoverage-mapping \
    -emit-llvm -S \
    -c program.bpf.c \
    -o program.bpf.ll
```

Notice it doesn't matter if you use the textual (`*.ll`) or the binary form (`*.bc`).
Obviously, the former is more readable.

The same logic applies to `opt`: by default it generates `*.bc`.
Using the `-S` flag you can obtain the output in textual form (`*.ll`).

Anyhow, it's time to run the LLVM pass on the LLVM IR we obtained.

Let's do it:

```bash
opt -load-pass-plugin $(BUILD_DIR)/lib/libBPFCov.so -passes="bpf-cov" \
    -S program.bpf.ll \
    -o program.bpf.cov.ll
```

We should have obtained a new LLVM IR that's now valid and loadable from the BPF VM in the Linux kernel. Almost there, YaY!

From it, we can obtain a valid BPF ELF now:

```bash
llc -march=bpf -filetype=obj -o cov/program.bpf.o program.bpf.cov.ll
```

While we are at it, it is also worth running the LLVM pass again (with a flag) to obtain another BPF ELF containing all the **profiling** and **coverage mapping** info.
It will come in handy later with `llvm-cov`.

```bash
opt -load $(BUILD_DIR)/lib/libBPFCov.so -strip-initializers-only -bpf-cov \
    program.bpf.ll | \
    llc -march=bpf -filetype=obj -o cov/program.bpf.obj
```

At this point, we can compile our userspace application loading the eBPF instrumented program (`cov/program.bpf.o`).

Doing this when using `libbpf` and skeletons is very easy. Nothing different from the common steps: `bpftool`, `cc`, etc.

In the [examples](examples/) directory, you can find further explainations.

So assuming we got our instrumented binary ready (`cov/program`), we can run it via the `bpfcov` CLI.

```bash
sudo ./bpfcov run cov/program
# Wait for it to exit, or stop it with CTRL+C
sudo ./bpfcov gen --unpin cov/program
```

Again, in case you wanna know more about these 2 steps, refer this time to the [CLI README](cli/README.md).

Now we have a magic `cov/program.profraw` file...

And we can use the LLVM toolchain to generate very fine-grained coverage reports like those in the screenshots!

Refer to the [LLVM docs](https://clang.llvm.org/docs/SourceBasedCodeCoverage.html#creating-coverage-reports) to learn how to do it.

But no worries, it's just about invoking `llvm-profdata` and `llvm-cov`:

```bash
lvm-profdata merge -sparse cov/program.profraw -o cov/program.profdata
llvm-cov show \
    --format=html \
    --show-line-counts-or-regions --show-region-summary --show-branch-summary \
    --instr-profile=cov/profdata.profdata \
    -object cov/program.bpf.obj \
    --output-dir=cov/html_report
```


## Development Environment

In order to **build** the BPFCov library (`libBPFCov.so`) you will need:

- LLVM 12+
- CMake 3.13.4+
- C++ compiler that supports C++14

In order to **use** it, you will need:

- clang 12 (to generate the input LLVM files)
- its [opt](http://llvm.org/docs/CommandGuide/opt.html) binary to run the LLVM pass

This project has been tested on Arch Linux (5.15).

## Building

Build as follows:

```console
mkdir -p build && cd build
cmake -DLT_LLVM_INSTALL_DIR=/path/to/llvm/installation ..
make
```

Notice that the `LT_LLVM_INSTALL_DIR` variable should be set to the root of either the installation (usually `/usr`) or the build directory of LLVM.

It is used to locate the corresponding `LLVMConfig.cmake` script that is used to set the include and the
library paths.

## Testing

To run the tests you will need to install **llvm-lit**.

Usually, you can install it with **pip**:

```console
pip install lit
```

Running the tests is as simple as:

```console
lit build/test
```


