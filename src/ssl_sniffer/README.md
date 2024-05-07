# SSL Sniffer

> [!NOTE]
> Still in WIP. A `bpftrace_demo.sh` script is provided to try to sniff any encrypted messages on a provided program.
> Run the script with `sudo ./bpftrace_demo.sh <program_name/path>`.

`ssl_sniffer` is a simple tool to sniff on-going SSL/TLS traffic on the machine without installing, trusting, or modifying any certificate. It will **intercept the SSL/TLS traffic** and **decrypt it** on the fly at the system SSL libraries level.

> [!IMPORTANT]
> Despite trying to sniff most of the SSL/TLS traffic, some applications might not be appearing in the traffic. This is because the application might be **using a different non supported SSL/TLS library**, **bringing their own library** in a directory which is not being sniffed or are **statically compiled** with the SSL/TLS library.
