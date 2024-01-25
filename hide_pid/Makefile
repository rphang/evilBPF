APPS  := hide_pid
EBPF  := hider
ROOTDIR := $(abspath $(CURDIR)/../)

finder: finder.c
	gcc -o finder finder.c -static

include $(ROOTDIR)/common.mk