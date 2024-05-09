# SSL Sniffer

> [!NOTE]
> Still in WIP. A `bpftrace_demo.sh` script is provided to try to sniff any encrypted messages on a provided program.
> Run the script with `sudo ./bpftrace_demo.sh <program_name/path>`.

`ssl_sniffer` is a simple tool to sniff on-going SSL/TLS traffic on the machine without installing, trusting, or modifying any certificate. It will **intercept the SSL/TLS traffic** and **decrypt it** on the fly at the system SSL libraries level.

> [!IMPORTANT]
> Despite trying to sniff most of the SSL/TLS traffic, some applications might not be appearing in the traffic. This is because the application might be **using a different non supported SSL/TLS library**, **bringing their own library** in a directory which is not being sniffed or have **inbuilt SSL/TLS support**.

# Steps

- for every running KNOWN process to sniff, we will:
  - Listen for the `connect` syscall and store the file descriptor IF its a remote connection (may think about local connections later)
  - Linkage of the SSL/TLS library to the TCP file descriptor:
    - (OpenSSL) Listen for the `SSL_set_fd` function call and store the SSL context linked to the file descriptor
    - (GnuTLS) Listen for the `gnutls_transport_set_ptr` function call and store the SSL context linked to the file descriptor
    - (NSS) Listen for the `PRFileDesc` structure and store the SSL context linked to the file descriptor
  - Listen for the equivalent `SSL_read` and `SSL_write` function calls and decrypt the data linked to the SSL context we stored earlier.

We now know the outgoing/incoming data of any SSL/TLS connection on the machine and their destination.