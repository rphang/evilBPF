# Makefile for eBPF ICMP pingback program

TARGET  := icmp_pingback
BPF_SRC := $(wildcard *.bpf.c)
SRC     := $(filter-out $(BPF_SRC), $(wildcard *.c))
ARCH	:= $(shell uname -m)
CFLAGS  ?= -Wall -O2 -g -static
LDFLAGS ?= 
LIBS     = -I../lib/libbpf/src -L../lib/libbpf/src/ -l:libbpf.a -lelf -lz

all: bpf user-space

.PHONY: clean
clean:
	rm -f *.o $(TARGET) vmlinux.h

# Build the user-space program
user-space: $(SRC)
	clang -Wall -O2 -g -o $(TARGET) $(SRC) $(LIBS) $(CFLAGS) $(LDFLAGS)

# Build the eBPF program
bpf: $(BPF_SRC) vmlinux.h
	clang -O2 -g -Wall -target bpf -I . -I../lib/libbpf/src -D__TARGET_ARCH_x86_64 -c $<

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

debug:
	cat /sys/kernel/debug/tracing/trace_pipe