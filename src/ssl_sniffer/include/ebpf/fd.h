#ifndef __FD_H
#define __FD_H

#include "vmlinux.h"

// fd types
#define FD_TYPE_CONNECT 1
#define FD_TYPE_ACCEPT 2

// Socket types
// STREAM like (TCP)
#define SOCK_STREAM 1
#define SOCK_SEQPACKET 5
#define SOCK_RAW 3
// DGRAM like (UDP)
#define SOCK_DGRAM 2
#define SOCK_RDM 4
#define SOCK_PACKET 10

// Address families
#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6 10

/**
 * @brief Structure to store file descriptor events for connect() & accept() syscalls
 */
struct fd_event
{
    int type;
    u64 ts;
    u64 pidtgid;
    int con_type;
    int family;
    unsigned short int port;
    unsigned char dst_ipv4[4];
    unsigned short int dst_ipv6[8];
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64); // pidtgid << 32 | sockfd
    __type(value, struct fd_event);
    __uint(max_entries, 1024);
} fd_events_maps SEC(".maps");

#endif