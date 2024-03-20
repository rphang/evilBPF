APPS  := hide_pid
EXTRA_APPS := finder
EBPF  := hider
ROOTDIR := $(abspath $(CURDIR)/../)

all: $(APPS) finder

finder: finder.c
	$(call msg,BINARY,$@)
	clang -Wall -O2 $@.c -o $@ -static
	strip $@

include $(ROOTDIR)/common.mk