
clean:
	find . -mindepth 2 -name libbpf -prune -o -name Makefile -execdir make clean \;

.PHONY: clean
