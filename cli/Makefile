.POSIX:
CC     = cc
CFLAGS = -std=c11 -Wall -Wextra -O3 -g3 -I../examples/src/.output #-DNDEBUG

bpfcov: bpfcov.c
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $< -lbpf