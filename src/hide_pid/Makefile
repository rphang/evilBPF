APPS  := hider
EXTRA_APPS := finder
EBPF  := prog
ROOTDIR := $(abspath $(CURDIR)/../)

all: $(APPS) finder

finder: finder.c
	$(call msg,BINARY,$@)
	clang -Wall -O2 $@.c -o $@ -static
	strip $@

include $(ROOTDIR)/common.mk