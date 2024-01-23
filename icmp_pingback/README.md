# icmp_pingback

This is a set of simple programs to demonstrate how to write eBPF programs that make use of XDP to implement a simple ICMP pingback service.

It is intended to show incrementally the features of eBPF and XDP, and how they can be used to implement a simple service. (bare minimum, use of skeleton, use of maps, etc.)

## Variants

> **Note:** These are all CO-RE compatible, the only requirement is that your system have `vmlinux` available to compile.

All variants kinda based on the same code, but each one adds a way to load or uses a new eBPF feature.

| Variant | Description |
| ------- | ----------- |
| [minimum](minimum) | The bare minimum to get a working XDP program. (no maps, no skel) |
| [maps](maps) | Adds a map to the program to enable/disable the pingback service on runtime. |
