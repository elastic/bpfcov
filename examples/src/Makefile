OUTPUT := .output
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
CLANG ?= clang
OPT ?= opt
LLC ?= llc
BPFCOVLIB_DIR ?= $(abspath ../../build/lib)
BPFTOOL_LOCAL ?= ../tools/bpftool
BPFTOOL = $(abspath $(BPFTOOL_LOCAL))
LIBBPF_DIR := $(abspath ../libbpf)
LIBBPF_SRC := $(abspath $(LIBBPF_DIR)/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
VMLINUX := $(abspath $(OUTPUT)/vmlinux/vmlinux.h)
INCLUDES := -I$(OUTPUT) -I$(LIBBPF_DIR)/include/uapi -I$(dir $(VMLINUX))
ROOT_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

# List your examples here
EXAMPLES = raw_enter fentry

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

BINARIES := $(patsubst %,$(OUTPUT)/%,$(EXAMPLES))

.PHONY: all
all: $(EXAMPLES)

.PHONY: distclean
distclean:
	$(call msg,DISTCLEAN)
	$(Q)rm -rf $(OUTPUT)
	$(Q)unlink $(BPFTOOL)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT)/*.bpf.{o,ll,cov.o,cov.ll}
	$(Q)rm -rf $(OUTPUT)/*.skel.{h,cov.h}
	$(Q)rm -rf $(OUTPUT)/*.cov.{o,c,obj} $(OUTPUT)/*.o $(OUTPUT)/*.cov
	$(Q)rm -rf $(BINARIES)

# Create output directory
$(OUTPUT) $(OUTPUT)/libbpf:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@) \
		INCLUDEDIR= LIBDIR= UAPIDIR= \
		install

# Link bpftool
$(BPFTOOL): $(shell command -v bpftool)
	$(call msg,BPFTOOL,$(BPFTOOL_LOCAL))
	$(Q)$(shell ln -s $< $@)

# Generate vmlinux.h
$(VMLINUX): $(BPFTOOL) /sys/kernel/btf/vmlinux
	$(call msg,MKDIR,$(dir $@))
	$(Q)mkdir -p $(dir $@)
	$(call msg,VMLINUX,$@)
	$(Q)$(BPFTOOL) btf dump file $(word 2,$^) format c > $@

# Compile the eBPF example as is
$(OUTPUT)/%.bpf.o: %.bpf.c $(wildcard %.h) $(VMLINUX) $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,OBJ,$@)
	$(Q)$(CLANG) -g -O2 \
		-target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
		-c $(filter %.c,$^) \
		-o $@

# Obtain the LLVM IR instrumenting profiling and coverage mappings
# -fprofile-instr-generate -mllvm -enable-name-compression=false -fcoverage-mapping
$(OUTPUT)/%.bpf.ll: %.bpf.c $(wildcard %.h) $(VMLINUX) $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,LL,$@)
	$(Q)$(CLANG) -g -O2 \
		-target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
		-fprofile-instr-generate -mllvm -enable-name-compression=false -fcoverage-mapping \
		-emit-llvm -S \
		-c $(filter %.c,$^) \
		-o $@

# Create the object file for coverage (not for loading)
$(OUTPUT)/%.bpf.cov.obj: $(OUTPUT)/%.bpf.ll | $(OUTPUT)
	$(call msg,COV.OBJ,$@)
	$(Q)$(OPT) \
		-load $(BPFCOVLIB_DIR)/libBPFCov.so -strip-initializers-only -bpf-cov $< \
		| $(LLC) -march=bpf -filetype=obj -o $@

# Make the LLVM IR valid for eBPF
$(OUTPUT)/%.bpf.cov.ll: $(OUTPUT)/%.bpf.ll | $(OUTPUT)
	$(call msg,COV,$@)
	$(Q)$(OPT) \
		-load-pass-plugin $(BPFCOVLIB_DIR)/libBPFCov.so -passes="bpf-cov" \
		-S $< -o $@

# Build the instrumented ELF
$(OUTPUT)/%.bpf.cov.o: $(OUTPUT)/%.bpf.cov.ll $(OUTPUT)/%.bpf.cov.obj | $(OUTPUT)
	$(call msg,OBJ,$@)
	$(Q)$(LLC) -march=bpf -filetype=obj -o $@ $<

# Generate the skeleton for the eBPF example as is
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o $(BPFTOOL) | $(OUTPUT)
	$(call msg,SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< name $(@F:.skel.h=) > $@

# Generate the skeleton for the instrumented ELF
$(OUTPUT)/%.skel.cov.h: $(OUTPUT)/%.bpf.cov.o $(BPFTOOL) | $(OUTPUT)
	$(call msg,SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< name $(@F:.skel.cov.h=) > $@

# Build userspace code
$(patsubst %,$(OUTPUT)/%.o,$(EXAMPLES)): %.o: %.skel.h
$(patsubst %,$(OUTPUT)/%.cov.o,$(EXAMPLES)): %.cov.o: %.skel.cov.h

# Build the eBPF application as is
$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) -g -Wall $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build the instrumented eBPF application
$(OUTPUT)/%.cov.c: %.c
	$(call msg,SED,$@)
	$(Q)sed -E '/^#include/ s/"$(@F:.cov.c=.skel)/&.cov/' $< > $@

$(OUTPUT)/%.cov.o: $(OUTPUT)/%.cov.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) -g -Wall $(INCLUDES) -I$(ROOT_DIR) -c $(filter %.c,$^) -o $@

# Build the binary as is
%: $(OUTPUT)/%.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BIN,$(OUTPUT)/$@)
	$(Q)$(CC) -g -Wall $^ -lelf -lz -o $(OUTPUT)/$@

# Build the instrumented eBPF binary
%.cov: $(OUTPUT)/%.cov.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BIN,$(OUTPUT)/$@)
	$(Q)$(CC) -g -Wall $^ -lelf -lz -o $(OUTPUT)/$@

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.bpf.ll, etc.) targets
.SECONDARY: