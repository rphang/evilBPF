# SSL Sniffer

`ssl_sniffer` is a simple tool to sniff on-going SSL/TLS traffic on the machine without installing, trusting, or modifying any certificate. It will **intercept the raw decrypted SSL/TLS traffic**, and display it on the fly.

![ssl_demo](../../.github/resources/ssl_sniffer_demo.gif)

## Features

- ✅ Sniff many SSL/TLS libraries (OpenSSL, GnuTLS, NSS)
- ✅ On-the-fly SSL/TLS traffic sniffing (no need to install certificates & restart the application)
- ✅ Bypass SSL Pinning
- 🚧 [**Planned**] protocol parsing (HTTP2+)

It supports out-of-the-box the following applications:
- `curl`
- `wget`
- `nginx` (not all versions, some have inbuilt SSL/TLS support)
- `php`, `python` (tested so far)
& many more...

## Usage

```bash
$ sudo ./ssl_sniffer
libssl.so probes attached to ...
```

From there, any application making uses of the system's SSL/TLS libraries will be sniffed. The output will be displayed on the terminal.

```bash
$ sudo ./ssl_sniffer
...
Press Ctrl+C to stop
[+] curl(12345), ts: 1234567890, op: SSL_OP_WRITE, len: 78 -->
GET / HTTP/1.1
Host: www.google.com
User-Agent: curl/7.81.0
Accept: */*


[+] curl(12345), ts: 1234567890, op: SSL_OP_READ, len: 1378 -->
HTTP/1.1 200 OK
Date: ...
Set-Cookie: ...
...
```

## How it works

`ssl_sniffer` is an eBPF program that will be attached to various uprobe and kprobe events to intercept the SSL/TLS traffic. It supports the following libraries:
- OpenSSL
- GnuTLS
- NSS

> [!IMPORTANT]
> Despite trying to sniff most of the SSL/TLS traffic, some applications might not be appearing in the traffic. This is because the application might be **using a different non supported SSL/TLS library**, **bringing their own library** in a directory which is not being sniffed or have **inbuilt SSL/TLS support**. It would still be possible to hijack them if we know their paths and trying to guess func. by their DWARF info.
>
> The hardest case is when the statically compiled application is using **non-standard SSL/TLS libraries** and have **no DWARF info**. In this case, it's better to give up unless we know the functions locations.

## Requirements

- Kernel version **>= 5.8** (could be lower but that requires to ditch ring buffer's and replace them with perf buffers)

Tested on:
- Ubuntu 22.04 LTS (kernel 5.15.0-106-generic)

## Extra

A `bpftrace_demo.sh` script is provided to try to sniff any encrypted SSL/TLS traffic on specified programs. It will use `bpftrace` to compile and load the eBPF program. It's a simplier version of the `ssl_sniffer` tool with truncated output.

## Technical Details

As we don't really know how big the SSL/TLS traffic is, going for size defined structures is not a good idea as we may either waste space for small packets or truncate big packets. To avoid this, `ssl_sniffer` uses a ring buffer and transfers the data from the kernel to the user space through chunks of constant size. These chunks are then reassembled in the user space to get the full packet (TODO).

> [!NOTE]
> This contains an implementation of [Google's Chunking Trick](https://lpc.events/event/11/contributions/938/attachments/909/1788/BPF_Security_Google.pdf) at the [Linux Plumbers Conference 2021](https://lpc.events/2021/).