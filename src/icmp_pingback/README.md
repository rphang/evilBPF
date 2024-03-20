# icmp_pingback

This is a set of simple programs to demonstrate how to write eBPF programs that make use of XDP to implement a simple ICMP pingback service.

It is intended to show incrementally the features of eBPF and XDP, and how they can be used to implement a simple service. (bare minimum, use of skeleton, use of maps, etc.)

## Versions

All versions kinda based on the same code, but each one adds a way to load or uses a new eBPF feature.

| Variant | Description |
| ------- | ----------- |
| [minimum](minimum) | The bare minimum to get a working XDP program. (no maps, no skel) |
| [maps](maps) | Adds a map to the program to enable/disable the pingback service on runtime. |

> [!NOTE]
> On my dev machine, my `vmlinux.h` file is generated without the `xdp_md` struct. I for now have no idea why this is the case, but I've found a workaround by simply
> redefining the `xdp_md` struct in the application code. This is not ideal, but it works for now. (You may need to remove it if you are not facing this issue)