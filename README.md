# evilBPF
_an eBPF / XDP Playground_

This repository contains a collection of eBPF / XDP programs that I've written while learning about eBPF and XDP. As security is my primary interest, most of these programs are security-related and are intended to be used for security research.

> **Disclaimer:** I condemn the use of these programs for malicious purposes. I am not responsible for any damage caused by the use of these programs. These programs are intended for educational purposes only.

## Programs

| Type | Name | Description | Notes |
| ---- | ---- | ----------- | ----- |
| XDP | [icmp_pingback](icmp_pingback) | Respond to ICMP echo requests with ICMP echo replies within the XDP layer. | multiple demo used to show the features offered by eBPF |
| TP | [hide_pid](hide_pid) | Hide a process (pid)/folder/file from the system | Heavily inspired by [bad-bpf](https://github.com/pathtofile/bad-bpf) with some modifications |
| TP | [hidden_ssh](hidden_ssh) | Add sneaky backdoor to SSH | W.I.P but Auth_key injection is there |

## Requirements

For compiling eBPF programs, you'll need the following:

- Debian, Ubuntu, or other Debian-based Linux distribution

```bash
sudo apt install clang llvm libelf-dev gcc-multilib linux-headers-$(uname -r) build-essential
```

Make sure that the version of `clang` and `llvm` installed is `>= 10.0.0`.

## Installation

### Getting the source code

As we are using submodules, you'll need to clone this repository with the `--recursive` flag:

```bash
git clone https://github.com/rphang/evilBPF.git --recursive
```

If you've already cloned this repository without the `--recursive` flag, you can run the following command to clone the submodules:

```bash
git submodule update --init --recursive
```

### Compiling the programs

Each program has its own directory, and each directory has its own `Makefile`. To compile a program, simply `cd` into the program's directory and run `make`:

```bash
cd <program>...
make
```

This will compile the program and generate the following files:
- **`<program>`**: The application that loads the eBPF program.
- **`<program>.bpf.o`**: The compiled eBPF program.
- **`<program>.skel.h`**: The skeleton code for the eBPF program.
- **`vmlinux.h`**: The kernel headers for the kernel version that you are running.

## Known issues

On my dev machine, my `vmlinux.h` file is generated without the `xdp_md` struct. I for now have no idea why this is the case, but I've found a workaround by simply
redifining the `xdp_md` struct in the application code. This is not ideal, but it works for now. (You may need to remove it if you are not facing this issue)


## Roadmap & Ideas

- [2/x] Compatible with [bpf CO-RE](https://nakryiko.com/posts/bpf-core-reference-guide/) ?
- [ ] Steal nginx passwd, authorization header, and cookie with openssl support (uprobes)
- [ ] Shadow reading files (a kind of a kernel MITM sniffer)

## Resources

Alot of the general resources I've used to learn about eBPF and XDP are listed below:

- [libbpf-bootstrap: demo BPF applications](https://github.com/libbpf/libbpf-bootstrap) by [libbpf team](https://github.com/libbpf)
- [xdp-tutorial](https://github.com/xdp-project/xdp-tutorial) by [XDP-project team](https://github.com/xdp-project)
- [Simple eBPF CO-RE Application](https://www.sartura.hr/blog/simple-ebpf-core-application/) by Juraj Vijtiuk ([Sartura](https://www.sartura.hr/))