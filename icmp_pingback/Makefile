# Makefile for eBPF ICMP pingback program

TARGET  := icmp_pingback
BPF_SRC := $(wildcard *.bpf.c)
SRC     := $(filter-out $(BPF_SRC), $(wildcard *.c))
ARCH	:= $(shell uname -m)
CFLAGS  ?= -g
LDFLAGS ?= 
LIBS     = -lbpf -lxdp

all: bpf user-space

.PHONY: clean
clean:
	rm -f *.o $(TARGET)

# Build the user-space program
user-space: $(SRC)
	clang -Wall -O2 -g -o $(TARGET) $(SRC) $(CFLAGS) $(LDFLAGS) $(LIBS)

# Build the eBPF program
bpf: $(BPF_SRC)
	clang -O2 -g -Wall -target bpf -c $<

debug:
	cat /sys/kernel/debug/tracing/trace_pipe