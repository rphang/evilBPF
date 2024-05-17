#ifndef __FD_H
#define __FD_H

#include "vmlinux.h"

// STREAM like (TCP)
#define SOCK_STREAM 1
#define SOCK_SEQPACKET 5
#define SOCK_RAW 3

// DGRAM like (UDP)
#define SOCK_DGRAM 2
#define SOCK_RDM 4
#define SOCK_PACKET 10

#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6 10

struct connect_event
{
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
    __type(value, struct connect_event);
    __uint(max_entries, 1024);
} connect_events_maps SEC(".maps");

#endif