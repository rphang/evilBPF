ARCH 		?= $(shell uname -m)
LIBBPF_PATH  = $(ROOTDIR)/lib/libbpf/src
LIBBPF_FLAGS = -I$(LIBBPF_PATH) -L$(LIBBPF_PATH) -l:libbpf.a

all: $(APPS)

# Build application binary
$(APPS): %: | $(EBPF).skel.h
	$(call msg,BINARY,$@)
	clang -Wall -O2 -g $@.c $(CFLAGS) $(LIBBPF_FLAGS) -lelf -lz -o $@ -static

# eBPF skeleton
$(EBPF).skel.h: $(EBPF).bpf.o
	$(call msg,GEN-SKEL,$@)
	bpftool gen skeleton $< > $@

# build eBPF object file
$(EBPF).bpf.o: $(EBPF).bpf.c vmlinux.h
	$(call msg,BPF,$@)
	clang -O2 -g -Wall -target bpf -D__KERNEL__ -D__TARGET_ARCH_$(ARCH) -I . $(INCLUDES) $(COMMON_INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	llvm-strip -g $@

vmlinux.h:
	$(call msg,VMH, $@)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	rm -f $(APPS) $(EBPF).bpf.o $(EBPF).skel.h vmlinux.h

debug:
	cat /sys/kernel/debug/tracing/trace_pipe

.PHONY: clean debug