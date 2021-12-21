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
INCLUDES := -I$(LIBBPF_DIR)/include/uapi -I$(dir $(VMLINUX))
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

# List your examples here
EXAMPLES = raw_enter #fentry

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

.PHONY: all
all: $(EXAMPLES)

.PHONY: cov
cov: $(patsubst %,cov/%,$(EXAMPLES))

.PHONY: distclean
distclean:
	$(call msg,DISTCLEAN)
	$(Q)rm -rf $(OUTPUT)
	$(Q)unlink $(BPFTOOL)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT)/*.{o,bpf.o,skel.h}
	$(Q)rm -rf $(OUTPUT)/cov
	$(Q)rm -rf $(patsubst %,$(OUTPUT)/%,$(EXAMPLES))

# Create output directory
$(OUTPUT) $(OUTPUT)/cov $(OUTPUT)/libbpf:
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
		-target bpf -D__TARGET_ARCH_$(ARCH) -I$(OUTPUT) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
		-c $(filter %.c,$^) \
		-o $@

# Obtain the LLVM IR instrumenting profiling and coverage mappings
$(OUTPUT)/cov/%.bpf.ll: %.bpf.c $(wildcard %.h) $(VMLINUX) $(LIBBPF_OBJ) | $(OUTPUT)/cov
	$(call msg,LL,$@)
	$(Q)$(CLANG) -g -O2 \
		-target bpf -D__TARGET_ARCH_$(ARCH) -I$(OUTPUT)/cov $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
		-fprofile-instr-generate -fcoverage-mapping \
		-emit-llvm -S \
		-c $(filter %.c,$^) \
		-o $@

# Create the object file for coverage (not for loading, only for llvm-cov)
$(OUTPUT)/cov/%.bpf.obj: $(OUTPUT)/cov/%.bpf.ll | $(OUTPUT)/cov
	$(call msg,ARCHIVE,$@)
	$(Q)$(OPT) \
		-load $(BPFCOVLIB_DIR)/libBPFCov.so -strip-initializers-only -bpf-cov $< \
		| $(LLC) -march=bpf -filetype=obj -o $@

# Make the LLVM IR valid for eBPF
$(OUTPUT)/cov/%.bpf.cov.ll: $(OUTPUT)/cov/%.bpf.ll | $(OUTPUT)/cov
	$(call msg,COV,$@)
	$(Q)$(OPT) \
		-load-pass-plugin $(BPFCOVLIB_DIR)/libBPFCov.so -passes="bpf-cov" \
		-S $< -o $@

# Build the instrumented ELF
$(patsubst %,$(OUTPUT)/cov/%.bpf.o,$(EXAMPLES)): %.bpf.o: %.bpf.cov.ll %.bpf.obj
$(OUTPUT)/cov/%.bpf.o: $(OUTPUT)/cov/%.bpf.cov.ll | $(OUTPUT)/cov
	$(call msg,OBJ,$@)
	$(Q)$(LLC) -march=bpf -filetype=obj -o $@ $<

# Generate the skeleton for the eBPF example as is
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o $(BPFTOOL) | $(OUTPUT)
	$(call msg,SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< name $* > $@

# Generate the skeleton for the instrumented ELF
$(OUTPUT)/cov/%.skel.h: $(OUTPUT)/cov/%.bpf.o $(BPFTOOL) | $(OUTPUT)/cov
	$(call msg,SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< name $* > $@

# Build userspace code
$(patsubst %,$(OUTPUT)/%.o,$(EXAMPLES)): %.o: %.skel.h

# Build the eBPF application as is
$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) -g -Wall -I$(OUTPUT) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build userspace code using the instrumented skeleton
$(patsubst %,$(OUTPUT)/cov/%.o,$(EXAMPLES)): %.o: %.skel.h

# Build the instrumented eBPF application
$(OUTPUT)/cov/%.o: %.c $(wildcard %.h) | $(OUTPUT)/cov
	$(call msg,CC,$@)
	$(Q)$(CC) -g -Wall -I$(OUTPUT)/cov $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build the binary as is
%: $(OUTPUT)/%.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BIN,$(OUTPUT)/$@)
	$(Q)$(CC) -g -Wall $^ -lelf -lz -o $(OUTPUT)/$@

# Build the instrumented eBPF binary
cov/%: $(OUTPUT)/cov/%.o $(LIBBPF_OBJ) | $(OUTPUT)/cov
	$(call msg,BIN,$(OUTPUT)/$@)
	$(Q)$(CC) -g -Wall $^ -lelf -lz -o $(OUTPUT)/$@

# Delete failed targets
.DELETE_ON_ERROR:

# Keep intermediate (.bpf.o, etc.) targets
.SECONDARY:
