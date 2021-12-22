CC ?= cc
LIBBPF_DIR := $(abspath ../examples/libbpf)
LIBBPF_OBJ := $(abspath ../examples/src/.output/libbpf.a)
CFLAGS := -std=c11 -Wall -Wextra -O3 -g3

PROGRAM = bpfcov

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

ifeq ($(RELEASE),1)
	CFLAGS += -DNDEBUG
endif

.PHONY: all
all: $(PROGRAM)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(PROGRAM)

%: %.c $(LIBBPF_OBJ)
	$(call msg,BIN,$@)
	$(Q)$(CC) $(CFLAGS) $^ -lelf -lz -o $@
