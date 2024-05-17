ARCH 		?= $(shell uname -m|sed 's/x86_64/x86/'|sed 's/aarch64/arm/')
LIBBPF_PATH  = $(ROOTDIR)/../lib/libbpf/src
LIBBPF_FLAGS = -I$(LIBBPF_PATH) -L$(LIBBPF_PATH) -l:libbpf.a -lbpf
COMMON_INCLUDES = -I.
RELEASE_DIR  = $(ROOTDIR)/../dst

all: vmlinux.h $(APPS)

release_dest: $(APPS)
	mkdir -p $(RELEASE_DIR)
	cp $(APPS) $(RELEASE_DIR)

release: release_dest
	make clean

%.o: %.c
	$(call msg,CC,$@)
	clang -Wall -O2 $(CFLAGS) -c $< -o $@ $(INCLUDES) $(COMMON_INCLUDES)

# Build application binary
$(APPS): %: | $(APPS).skel.h libbpf $(OBJ)
	$(call msg,BINARY,$@)
	clang -Wall -O2 $@.c $(CFLAGS) $(OBJ) $(LIBBPF_FLAGS) -lelf -lz -o $@ -static
	strip $@

# eBPF skeleton
$(APPS).skel.h: $(APPS).bpf.o
	$(call msg,GEN-SKEL,$@)
	bpftool gen skeleton $< > $@

$(APPS).bpf.o: $(EBPF)
	@echo "Building $@"
	$(call msg,BPF,$@)
	bpftool gen object $@ $(addsuffix .bpf.o, $^)

# build each eBPF object file
$(EBPF): %.bpf.o: %.bpf.c
	@echo "Building(2) $@"
	$(call msg,BPF,$@)
	clang -O2 -g -Wall -target bpf -D__KERNEL__ -D__TARGET_ARCH_$(ARCH) $(CFLAGS) $(INCLUDES) $(COMMON_INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $@.bpf.c -o $@.bpf.o
	llvm-strip -g --strip-unneeded $@.bpf.o

vmlinux.h:
	$(call msg,VMH, $@)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

libbpf:
	make -C $(LIBBPF_PATH)

clean:
	@for prog in $(EBPF); do \
		rm -f $$prog.bpf.o; \
		rm -f $$prog.skel.h; \
	done
	rm -f $(APPS) vmlinux.h $(EXTRA_APPS) $(OBJ) $(APPS).bpf.o $(APPS).skel.h

xdpstatus:
	watch -n 0.5 bpftool net

debug:
	cat /sys/kernel/debug/tracing/trace_pipe

.PHONY: clean debug xdpstatus