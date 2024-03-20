
all:
	find . -mindepth 2 -name libbpf -prune -o -name Makefile -execdir make release \; || exit 1

clean:
	find . -mindepth 2 -name libbpf -prune -o -name Makefile -execdir make clean \;
	rm -rf dst;

.PHONY: clean
