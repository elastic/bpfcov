# bpfcov

> Catchy description here

This project provides 2 things

1. **libBPFCov.so** - an **out-of-tree** LLVM pass that builds against a binary LLVM installation.
2. **libbpf-cov** - a C library to collect coverage of your eBPF programs.

## Usage

Once you have [built](#building) the **bpfcov** LLVM pass, you can use it as follows:

```console
export LLVM_DIR=/path/to/llvm/installation
# Textual form
$LLVM_DIR/bin/clang ...
# Binary form
$LLVM_DIR/bin/clang ...
```

Notice it doesn't matter if you use the textual (`*.ll`) or binary form (`*.bc`).
Obviously, the former is more readable.

The same logic applies to **opt**: by default it generates `*.bc`.
Using the `-S` flag you can obtain the output in textual form (`*.ll`).

## Development Environment

In order to build **bpfcov** you will need:

- LLVM 12+
- CMake 3.13.4+
- C++ compiler that supports C++14

In order to run the **bpfcov** LLVM pass you will need:

- clang-12 (to generate the input LLVM files)
- [opt](http://llvm.org/docs/CommandGuide/opt.html) to run the pass

This project has been tested on ...

## Building

Build as follows:

```console
mkdir -p build && cd build
cmake -DLT_LLVM_INSTALL_DIR=/path/to/llvm/installation ..
make
```

Notice that the `LT_LLVM_INSTALL_DIR` variable should be set to the root of either the installation or build directory of LLVM.

It is used to locate the corresponding `LLVMConfig.cmake` script that is used to set the include and
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


