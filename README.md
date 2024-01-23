# eBPF / XDP Playground

This repository contains a collection of eBPF / XDP programs that I've written while learning about eBPF and XDP. As security is my primary interest, most of these programs are security-related and are intended to be used for security research.

> **Disclaimer:** I condemn the use of these programs for malicious purposes. I am not responsible for any damage caused by the use of these programs. These programs are intended for educational purposes only.

## Programs

| Type | Name | Description |
| ---- | ---- | ----------- |
| XDP | [icmp_pingback](icmp_pingback) | Respond to ICMP echo requests with ICMP echo replies within the XDP layer. |

## Requirements

For compiling eBPF programs, you'll need the following:

- Debian, Ubuntu, or other Debian-based Linux distribution

```bash
sudo apt install clang llvm libelf-dev libbpf-dev gcc-multilib linux-headers-$(uname -r) build-essential
```

You may not have all of the above packages in your distribution's package repository. If that's the case, you'll need to compile and install the following packages from source:

- [libbpf](https://github.com/libbpf/libbpf)

## Roadmap

- [ ] Compatible with [bpf CO-RE](https://nakryiko.com/posts/bpf-core-reference-guide/) ?

## Resources

Alot of the resources I've used to learn about eBPF and XDP are listed below:

- [libbpf-bootstrap: demo BPF applications](https://github.com/libbpf/libbpf-bootstrap) by [libbpf team](https://github.com/libbpf)
- [xdp-tutorial](https://github.com/xdp-project/xdp-tutorial) by [XDP-project team](https://github.com/xdp-project)
- [Simple eBPF CO-RE Application](https://www.sartura.hr/blog/simple-ebpf-core-application/) by Juraj Vijtiuk ([Sartura](https://www.sartura.hr/))