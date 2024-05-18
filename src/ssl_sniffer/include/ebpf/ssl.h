#ifndef __SSL_H
#define __SSL_H

#include <vmlinux.h>

// FD <-> SSL struct ( <-> R/W event)
/*
 * This map is used to store the SSL struct pointer for each FD.
 * The key is the FD and the value is the SSL struct pointer.
 */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *);
    __type(value, int);
    __uint(max_entries, 1024);
} ssl_to_fd SEC(".maps");

#endif